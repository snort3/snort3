set( FILE_LIST
    extractor.cc
    extractor.h
    extractor_csv_logger.cc
    extractor_csv_logger.h
    extractor_event_handlers.h
    extractor_http_event_handler.cc
    extractor_json_logger.cc
    extractor_json_logger.h
    extractor_logger.cc
    extractor_logger.h
    extractor_service.cc
    extractor_service.h
    extractor_writer.cc
    extractor_writer.h
)

add_library(extractor OBJECT ${FILE_LIST})
