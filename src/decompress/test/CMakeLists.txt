add_cpputest( file_olefile_test
    SOURCES ../file_olefile.cc
            ../file_oleheader.cc
            ../../helpers/boyer_moore_search.cc
)

add_cpputest(file_oleheader_test
    SOURCES ../file_oleheader.cc
)

