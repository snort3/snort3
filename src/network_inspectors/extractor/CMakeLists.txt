set( FILE_LIST
    extractor.cc
    extractor.h
    extractor_csv_logger.cc
    extractor_csv_logger.h
    extractor_enums.h
    extractor_flow_data.cc
    extractor_flow_data.h
    extractor_ftp.cc
    extractor_http.cc
    extractor_json_logger.cc
    extractor_json_logger.h
    extractor_logger.cc
    extractor_logger.h
    extractor_service.cc
    extractor_service.h
    extractors.cc
    extractors.h
    extractor_null_conn.h
)

add_library(extractor OBJECT ${FILE_LIST})
