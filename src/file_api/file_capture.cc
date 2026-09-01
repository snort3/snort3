//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
/*
 **
 **  Author(s):  Hui Cao <huica@cisco.com>
 **
 **  NOTES
 **  5.05.2013 - Initial Source Code. Hui Cao
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_capture.h"

#include <sys/stat.h>

#include <cassert>

#include "log/messages.h"
#include "main/thread.h"
#include "utils/stats/snapshot.h"
#include "utils/util.h"

#include "file_mempool.h"
#include "file_stats.h"

#ifdef UNIT_TEST
#include <atomic>
#include <memory>
#include <set>

#include "catch/snort_catch.h"
#endif

using namespace snort;

FileMemPool* FileCapture::file_mempool = nullptr;
int64_t FileCapture::capture_block_size = 0;

std::mutex FileCapture::capture_mutex;
std::condition_variable FileCapture::capture_cv;
std::thread* FileCapture::file_storer = nullptr;
std::queue<FileCapture*> FileCapture::files_waiting;
bool FileCapture::file_storing = false;
bool FileCapture::running = true;

#ifdef UNIT_TEST
static void (*writer_test_hook)() = nullptr;
static void (*writer_idle_test_hook)() = nullptr;
static void (*flush_entry_test_hook)() = nullptr;
static void (*flush_predicate_test_hook)(bool, bool) = nullptr;
#endif

FileCaptureState FileCapture::error_capture(FileCaptureState state)
{
    file_counts.file_reserve_failures++;
    return state;
}

// Only one writer thread supported
void FileCapture::writer_thread()
{
    SET_THREAD_NAME(pthread_self(), "snort3.filecap");

    while (true)
    {
        // Wait until there are files
        std::unique_lock<std::mutex> lk(capture_mutex);
        capture_cv.wait(lk, [] { return !running or !files_waiting.empty(); });

        // When !running we write out any remaining files before exiting.
        // FIXIT-L should take dirty_pig into account. But this thread does not have convenient
        // access to snort_conf.
        if (files_waiting.empty())
            break;

        FileCapture* file = files_waiting.front();
        files_waiting.pop();
        file_storing = true;
        lk.unlock();

#ifdef UNIT_TEST
        if (writer_test_hook)
            writer_test_hook();
#endif

        file->store_file();
        delete file;

        lk.lock();
        file_storing = false;
        lk.unlock();
        capture_cv.notify_all();
#ifdef UNIT_TEST
        if (writer_idle_test_hook)
            writer_idle_test_hook();
#endif
        // coverity[double_unlock] : ~unique_lock is a no-op after explicit lk.unlock() above
    }
}

FileCapture::FileCapture(int64_t min_size, int64_t max_size)
{
    capture_size = 0;
    last = head = nullptr;
    current_data = nullptr;
    current_data_len = 0;
    capture_state = FILE_CAPTURE_SUCCESS;
    capture_min_size = min_size;
    capture_max_size = max_size;
}

FileCapture::~FileCapture()
{
    FileCaptureBlock* file_block = head;

    if (file_info)
        file_counts.files_released_total++;
    else
        file_counts.files_freed_total++;

    while (file_block)
    {
        FileCaptureBlock* next_block = file_block->next;
        if (file_info)
        {
            if (file_mempool->m_release(file_block) != FILE_MEM_SUCCESS)
                file_counts.file_buffers_release_errors++;
            file_counts.file_buffers_released_total++;
        }
        else
        {
            if (file_mempool->m_free(file_block) != FILE_MEM_SUCCESS)
                file_counts.file_buffers_free_errors++;
            file_counts.file_buffers_freed_total++;
        }

        file_counts.file_buffers_in_use = get_buffers_in_use();
        file_block = next_block;
    }

    head = last = nullptr;

    if (file_info)
        delete file_info;
}

void FileCapture::init(int64_t memcap, int64_t block_size)
{
    capture_block_size = block_size;
    init_mempool(memcap, capture_block_size);
    file_counts.file_buffers_max = get_buffers_max();
    file_storer = new std::thread(writer_thread);
}

/*
 *  Release all file capture memory etc,
 *  this must be called when snort exits
 */
void FileCapture::exit()
{
    {
        std::lock_guard<std::mutex> lk(capture_mutex);
        running = false;
    }
    capture_cv.notify_one();

    if (file_storer)
    {
        file_storer->join();
        delete file_storer;
        file_storer = nullptr;
    }
}

void FileCapture::flush()
{
    std::unique_lock<std::mutex> lk(capture_mutex);
#ifdef UNIT_TEST
    if (flush_entry_test_hook)
        flush_entry_test_hook();
#endif
    capture_cv.wait(lk, []
    {
#ifdef UNIT_TEST
        if (flush_predicate_test_hook)
            flush_predicate_test_hook(files_waiting.empty(), file_storing);
#endif
        return files_waiting.empty() and !file_storing;
    });
}

/*
 * Initialize the file memory pool
 *
 * Arguments:
 *    int64_t max_file_mem: memcap in megabytes
 *    int64_t block_len:  file block size (metadata size excluded)
 */
void FileCapture::init_mempool(int64_t max_file_mem, int64_t block_len)
{
    int64_t block_size = block_len + sizeof (FileCapture);

    if (block_size <= 0)
        return;

    /*Convert megabytes to bytes*/
    int64_t max_file_mem_in_bytes = max_file_mem * 1024 * 1024;

    if (block_size & 7)
        block_size += (8 - (block_size & 7));

    int max_files = max_file_mem_in_bytes / block_size;

    file_mempool = new FileMemPool(max_files, block_size);
}

inline FileCaptureBlock* FileCapture::create_file_buffer()
{
    if (!file_mempool)
        return nullptr;

    FileCaptureBlock* fileBlock = (FileCaptureBlock*)file_mempool->m_alloc();

    file_counts.file_buffers_in_use = get_buffers_in_use();

    if (fileBlock == nullptr)
    {
        file_counts.file_memcap_failures_total++;
        return nullptr;
    }

    file_counts.file_buffers_allocated_total++;

    fileBlock->length = 0;
    fileBlock->next = nullptr;     /*Only one block initially*/

    uint64_t num_files_queued = file_mempool->allocated();
    if (file_counts.file_buffers_used_max < num_files_queued)
        file_counts.file_buffers_used_max = num_files_queued;

    return fileBlock;
}

/*
 * Save file to the buffer
 * If file needs to be extracted, buffer will be reserved
 * If file buffer isn't sufficient, need to add another buffer.
 */
inline FileCaptureState FileCapture::save_to_file_buffer(const uint8_t* file_data,
    int data_size, int64_t max_size)
{
    FileCaptureBlock* lastBlock = last;
    int64_t available_bytes;

    if ( data_size <= 0 )
        return FILE_CAPTURE_SUCCESS;

    if ( data_size + (int64_t)capture_size > max_size)
    {
        file_counts.file_size_max++;
        capture_state = FILE_CAPTURE_MAX;
        return FILE_CAPTURE_MAX;
    }

    /* Check whether current file block can hold file data*/
    available_bytes = capture_block_size - lastBlock->length;

    if ( data_size > available_bytes)
    {
        FileCaptureBlock* new_block;
        const uint8_t* file_current = file_data;
        const uint8_t* file_end = file_data + data_size;

        /*can't hold all, use current block first*/
        memcpy(reinterpret_cast<uint8_t*>(lastBlock) + lastBlock->length + sizeof(*lastBlock),
            file_current, available_bytes);

        lastBlock->length = capture_block_size;
        file_current += available_bytes;

        /* We can support any file capture block size */
        while (true)
        {
            /*get another block*/
            new_block = static_cast<FileCaptureBlock*>(create_file_buffer());

            if (new_block == nullptr)
            {
                capture_state = FILE_CAPTURE_MEMCAP;
                return FILE_CAPTURE_MEMCAP;
            }

            last->next = new_block;
            last = new_block;

            /*Save data to the new block*/
            if (file_current + capture_block_size < file_end)
            {
                memcpy(reinterpret_cast<uint8_t*>(last) + sizeof(*new_block),
                    file_current,  capture_block_size);
                new_block->length =  capture_block_size;
                file_current += capture_block_size;
            }
            else
            {
                memcpy(reinterpret_cast<uint8_t*>(last) + sizeof(*new_block),
                    file_current,  file_end - file_current);

                new_block->length = file_end - file_current;
                break;
            }
        }
    }
    else
    {
        memcpy(reinterpret_cast<uint8_t*>(lastBlock) + lastBlock->length + sizeof(*lastBlock),
            file_data, data_size);

        lastBlock->length += data_size;
    }

    capture_size += data_size;

    return FILE_CAPTURE_SUCCESS;
}

/*
 * Save files to the local buffer first for files transferred
 * by multiple reassembled packets. For files within a packet,
 * simply using the packet buffer.
 * If file needs to be extracted, buffer will be reserved
 *
 * Arguments:
 *   FileContext* context: current file context
 *   uint8_t *file_data: current file data
 *   int data_size: current file data size
 *   FilePosition position: position of file data
 * Returns:
 *   0: successful
 *   1: fail to capture the file or file capture is disabled
 */
FileCaptureState FileCapture::process_buffer(const uint8_t* file_data,
    int data_size, FilePosition position)
{
    current_data = file_data;
    current_data_len = data_size;

    switch (position)
    {
    case SNORT_FILE_FULL:
        file_counts.file_within_packet++;
        break;
    case SNORT_FILE_END:
        break;
    default:

        /* For File position is either SNORT_FILE_START
         * or SNORT_FILE_MIDDLE,  the file is larger than one packet,
         * we need to store them into buffer.
         */
        if (!head)
        {
            head = last = create_file_buffer();

            if (!head)
            {
                return FILE_CAPTURE_MEMCAP;
            }

            file_counts.files_buffered_total++;
        }

        return (save_to_file_buffer(file_data, data_size, capture_max_size));
    }

    return FILE_CAPTURE_SUCCESS;
}

// Preserve the file in memory until it is released
FileCaptureState FileCapture::reserve_file(const FileInfo* file)
{
    uint64_t fileSize;

    if (capture_state != FILE_CAPTURE_SUCCESS)
    {
        return error_capture(capture_state);
    }

    FileCaptureBlock* fileBlock = head;

    /*
     * Note: file size is updated at this point
     */
    fileSize = file->get_file_size();

    if ( fileSize < (unsigned)capture_min_size)
    {
        file_counts.file_size_min++;
        return error_capture(FILE_CAPTURE_MIN);
    }

    if ( fileSize > (unsigned)capture_max_size)
    {
        file_counts.file_size_max++;
        return error_capture(FILE_CAPTURE_MAX);
    }

    /* Create a file buffer if it is not done yet,
     * This is the case for small file
     */
    if (!fileBlock)
    {
        fileBlock  = create_file_buffer();

        if (!fileBlock)
        {
            file_counts.file_memcap_failures_reserve++;
            return error_capture(FILE_CAPTURE_MEMCAP);
        }

        file_counts.files_buffered_total++;
        head = last = fileBlock;
    }

    /*Copy the last piece of file to file buffer*/
    if (save_to_file_buffer(current_data,
            current_data_len, capture_max_size) )
    {
        return error_capture(capture_state);
    }

    file_counts.files_captured_total++;

    current_block = head;

    file_info = new FileInfo(*file);

    return FILE_CAPTURE_SUCCESS;
}

/*
 * Get the file that is reserved in memory
 *
 * Arguments:
 *   uint8_t **buff: address to store buffer address
 *   int *size: address to store size of file
 *
 * Returns:
 *   the next memory block that stores file and its metadata
 *   nullptr: no more file data or fail to get file
 */
FileCaptureBlock* FileCapture::get_file_data(uint8_t** buff, int* size)
{
    assert(buff && size);
    if (current_block == nullptr)
    {
        *size = 0;
        *buff = nullptr;
        return nullptr;
    }

    *buff = reinterpret_cast<uint8_t*>(current_block) + sizeof(*current_block);
    *size = current_block->length;

    current_block = current_block->next;
    return (current_block);
}

/*
 * writing file data to the disk.
 *
 * In the case of interrupt errors, the write is retried, but only for a
 * finite number of times.
 */
// cppcheck-suppress constParameterPointer ; preserve the private installed-header declaration
void FileCapture::write_file_data(uint8_t* buf, size_t buf_len, FILE* fh)
{
    int max_retries = 3;
    size_t bytes_written = 0;
    int err;

    /* Nothing to write or nothing to write to */
    if ((buf == nullptr) || (fh == nullptr))
        return;

    /* writing several times */
    do
    {
        size_t bytes_left = buf_len - bytes_written;

        bytes_written += fwrite(buf + bytes_written, 1, bytes_left, fh);

        err = ferror(fh);
        if (err && (err != EINTR) && (err != EAGAIN))
        {
            break;
        }

        max_retries--;
    }
    while ((max_retries > 0) && (bytes_written < buf_len));

    if (bytes_written < buf_len)
    {
        ErrorMessage("File inspect: disk writing error - %s!\n", get_error(err));
    }
}

// Store files on local disk
void FileCapture::store_file()
{
    if (!file_info)
        return;

    const std::string& file_full_name = file_info->get_file_name();

    FILE* fh = fopen(file_full_name.c_str(), "wx");
    if (!fh)        
    {
        return;
    }
    // Check the file buffer
    uint8_t* buff = nullptr;
    int size = 0;
    const void* file_mem;

    do
    {
        file_mem = get_file_data(&buff, &size);
        // Get file from file buffer
        if (!buff || !size )
        {
            fclose(fh);
            return;
        }

        write_file_data(buff, size, fh);
    }
    while (file_mem);

    fclose(fh);
}

// Queue files to be stored to disk
std::string FileCapture::store_file_async()
{
    // send data to the writer thread
    if (!file_info)
        return std::string();

    const uint8_t* sha = file_info->get_file_sig_sha256();
    if (!sha)
        return std::string();

    std::string file_name = file_info->sha_to_string(sha);

    std::string file_full_name;
    get_instance_file(file_full_name, file_name.c_str());
    file_info->set_file_name(file_full_name.c_str(), file_full_name.size());

    std::lock_guard<std::mutex> lk(capture_mutex);
    files_waiting.push(this);
    capture_cv.notify_one();
    return file_full_name;
}

void FileCapture::collect_mem_usage(stats::Builder& builder, stats::Group& group)
{
    if (!file_mempool)
        return;

    int64_t block_size = get_block_size() + sizeof(FileCapture);
    if (block_size & 7)
        block_size += (8 - (block_size & 7));

    builder.counter(group, "Max file buffer capacity", file_mempool->total_objects());
    builder.counter(group, "Buffers in use", file_mempool->allocated());
    builder.counter(group, "Buffers in free list", file_mempool->freed());
    builder.counter(group, "Buffers in release list", file_mempool->released());
    builder.counter(group, "Memory usage in bytes", file_mempool->allocated() * block_size);
}

int64_t FileCapture::get_buffers_max()
{
    if (file_mempool)
        return file_mempool->total_objects();
    return 0;
}

int64_t FileCapture::get_buffers_in_use()
{
    if (file_mempool)
        return file_mempool->allocated();
    return 0;
}

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST
namespace snort
{
struct FileCaptureTestAccess
{
    static bool resettable()
    {
        std::lock_guard<std::mutex> lock(FileCapture::capture_mutex);
        return FileCapture::file_storer == nullptr and FileCapture::files_waiting.empty();
    }

    static void reset()
    {
        std::lock_guard<std::mutex> lock(FileCapture::capture_mutex);
        delete FileCapture::file_mempool;
        FileCapture::file_mempool = nullptr;
        FileCapture::capture_block_size = 0;
        FileCapture::file_storing = false;
        FileCapture::running = true;
    }

    static void enqueue(FileCapture* capture)
    {
        std::lock_guard<std::mutex> lock(FileCapture::capture_mutex);
        FileCapture::files_waiting.push(capture);
        FileCapture::capture_cv.notify_one();
    }

    static void enqueue(FileCapture* first, FileCapture* second)
    {
        std::lock_guard<std::mutex> lock(FileCapture::capture_mutex);
        FileCapture::files_waiting.push(first);
        FileCapture::files_waiting.push(second);
        FileCapture::capture_cv.notify_one();
    }

    static uint64_t released_buffers()
    {
        return FileCapture::file_mempool->released();
    }
};
}

class AsyncWriterGate
{
public:
    void writer_wait()
    {
        std::unique_lock<std::mutex> lock(mutex);
        writer_owns_capture = true;
        cv.notify_all();
        cv.wait(lock, [this] { return writer_released; });
    }

    void writer_idle()
    {
        std::unique_lock<std::mutex> lock(mutex);
        ++idle_transitions;
        cv.notify_all();
        if (pause_first_idle and idle_transitions == 1)
            cv.wait(lock, [this] { return idle_released; });
    }

    void flush_entered()
    {
        std::lock_guard<std::mutex> lock(mutex);
        flush_callers.emplace(std::this_thread::get_id());
        cv.notify_all();
    }

    void flush_predicate_evaluated(bool queue_empty, bool writer_active)
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!queue_empty and !writer_active)
            saw_nonempty_idle_evaluation = true;
        cv.notify_all();
    }

    void wait_for_writer()
    {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return writer_owns_capture; });
    }

    void wait_for_flush_callers(unsigned expected)
    {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this, expected] { return flush_callers.size() >= expected; });
    }

    void pause_first_idle_transition()
    {
        std::lock_guard<std::mutex> lock(mutex);
        pause_first_idle = true;
    }

    void wait_for_first_idle_transition()
    {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return idle_transitions >= 1; });
    }

    void wait_for_nonempty_idle_evaluation()
    {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return saw_nonempty_idle_evaluation; });
    }

    void release_writer()
    {
        std::lock_guard<std::mutex> lock(mutex);
        writer_released = true;
        cv.notify_all();
    }

    void release_idle_transition()
    {
        std::lock_guard<std::mutex> lock(mutex);
        idle_released = true;
        cv.notify_all();
    }

private:
    std::mutex mutex;
    std::condition_variable cv;
    std::set<std::thread::id> flush_callers;
    unsigned idle_transitions = 0;
    bool writer_owns_capture = false;
    bool writer_released = false;
    bool pause_first_idle = false;
    bool idle_released = false;
    bool saw_nonempty_idle_evaluation = false;
};

static AsyncWriterGate* async_writer_gate = nullptr;

static void wait_in_writer_test_hook()
{
    async_writer_gate->writer_wait();
}

static void wait_at_writer_idle_test_hook()
{
    async_writer_gate->writer_idle();
}

static void record_flush_entry_test_hook()
{
    async_writer_gate->flush_entered();
}

static void record_flush_predicate_test_hook(bool queue_empty, bool writer_active)
{
    async_writer_gate->flush_predicate_evaluated(queue_empty, writer_active);
}

class AsyncCaptureFixture
{
public:
    AsyncCaptureFixture()
    {
        const bool resettable = FileCaptureTestAccess::resettable();
        REQUIRE(resettable);
        FileCaptureTestAccess::reset();
        async_writer_gate = &gate;
        writer_test_hook = wait_in_writer_test_hook;
        writer_idle_test_hook = wait_at_writer_idle_test_hook;
        flush_entry_test_hook = record_flush_entry_test_hook;
        flush_predicate_test_hook = record_flush_predicate_test_hook;
        FileCapture::init(1, 64);
    }

    ~AsyncCaptureFixture() noexcept
    {
        gate.release_writer();
        gate.release_idle_transition();
        FileCapture::exit();
        writer_test_hook = nullptr;
        writer_idle_test_hook = nullptr;
        flush_entry_test_hook = nullptr;
        flush_predicate_test_hook = nullptr;
        async_writer_gate = nullptr;
        FileCaptureTestAccess::reset();
    }

    AsyncWriterGate gate;
};

TEST_CASE ("Should not segfault when file mempool is not configured", "[file_capture]")
{
    FileCapture fc(0, 0);

    CHECK(fc.process_buffer((const uint8_t*)"dummy", 5, SNORT_FILE_START) == FILE_CAPTURE_MEMCAP);
}

TEST_CASE ("Flush returns when no asynchronous captures are pending", "[file_capture]")
{
    FileCapture::flush();
}

TEST_CASE ("Flush waits for the asynchronous writer to release its capture", "[file_capture]")
{
    AsyncCaptureFixture fixture;

    auto capture = std::make_unique<FileCapture>(0, 128);
    const uint8_t data[] = { 0x01, 0x02, 0x03, 0x04 };
    REQUIRE(capture->process_buffer(data, sizeof(data), SNORT_FILE_START) ==
        FILE_CAPTURE_SUCCESS);

    FileInfo file;
    file.set_file_size(sizeof(data));
    REQUIRE(capture->reserve_file(&file) == FILE_CAPTURE_SUCCESS);
    REQUIRE(FileCapture::get_buffers_in_use() == 1);

    FileCaptureTestAccess::enqueue(capture.release());
    fixture.gate.wait_for_writer();

    std::atomic<unsigned> completed_flushes = 0;
    std::thread first_flush([&completed_flushes]
    {
        FileCapture::flush();
        ++completed_flushes;
    });
    std::thread second_flush([&completed_flushes]
    {
        FileCapture::flush();
        ++completed_flushes;
    });

    fixture.gate.wait_for_flush_callers(2);
    CHECK(completed_flushes == 0);
    CHECK(FileCapture::get_buffers_in_use() == 1);

    fixture.gate.release_writer();
    first_flush.join();
    second_flush.join();

    CHECK(completed_flushes == 2);
    file_counts_update_buffers();
    CHECK(file_counts.file_buffers_in_use == 0);
    CHECK(FileCapture::get_buffers_in_use() == 0);
    CHECK(FileCaptureTestAccess::released_buffers() == 1);
}

TEST_CASE ("Flush keeps waiting between queued asynchronous captures", "[file_capture]")
{
    AsyncCaptureFixture fixture;

    auto first_capture = std::make_unique<FileCapture>(0, 128);
    auto second_capture = std::make_unique<FileCapture>(0, 128);
    const uint8_t first_data[] = { 0x01 };
    const uint8_t second_data[] = { 0x02 };
    REQUIRE(first_capture->process_buffer(first_data, sizeof(first_data), SNORT_FILE_START) ==
        FILE_CAPTURE_SUCCESS);
    REQUIRE(second_capture->process_buffer(second_data, sizeof(second_data), SNORT_FILE_START) ==
        FILE_CAPTURE_SUCCESS);

    FileInfo first_file;
    first_file.set_file_size(sizeof(first_data));
    FileInfo second_file;
    second_file.set_file_size(sizeof(second_data));
    REQUIRE(first_capture->reserve_file(&first_file) == FILE_CAPTURE_SUCCESS);
    REQUIRE(second_capture->reserve_file(&second_file) == FILE_CAPTURE_SUCCESS);
    REQUIRE(FileCapture::get_buffers_in_use() == 2);

    FileCaptureTestAccess::enqueue(first_capture.release(), second_capture.release());
    fixture.gate.wait_for_writer();
    fixture.gate.pause_first_idle_transition();

    std::atomic<unsigned> completed_flushes = 0;
    std::thread flush([&completed_flushes]
    {
        FileCapture::flush();
        ++completed_flushes;
    });

    fixture.gate.wait_for_flush_callers(1);
    fixture.gate.release_writer();
    fixture.gate.wait_for_first_idle_transition();
    fixture.gate.wait_for_nonempty_idle_evaluation();

    CHECK(completed_flushes == 0);
    CHECK(FileCapture::get_buffers_in_use() == 1);

    fixture.gate.release_idle_transition();
    flush.join();

    CHECK(completed_flushes == 1);
    file_counts_update_buffers();
    CHECK(file_counts.file_buffers_in_use == 0);
    CHECK(FileCapture::get_buffers_in_use() == 0);
    CHECK(FileCaptureTestAccess::released_buffers() == 2);
}
#endif
