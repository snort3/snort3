find_package(PkgConfig)
pkg_check_modules(PC_RDKAFKA rdkafka)

if(NOT DEFINED RDKAFKA_INCLUDE_DIR_HINT)
  set(RDKAFKA_INCLUDE_DIR_HINT "" CACHE STRING "Hint for librdkafka include directory")
endif()
if(NOT DEFINED RDKAFKA_LIBRARIES_DIR_HINT)
  set(RDKAFKA_LIBRARIES_DIR_HINT "" CACHE STRING "Hint for librdkafka library directory")
endif()

if (PC_RDKAFKA_FOUND)
  set(RDKAFKA_LIBRARIES ${PC_RDKAFKA_LIBRARIES})
  set(RDKAFKA_INCLUDE_DIRS ${PC_RDKAFKA_INCLUDE_DIRS})
endif()

find_path(RDKAFKA_INCLUDE_DIR
  NAMES rdkafka.h
  HINTS ${RDKAFKA_INCLUDE_DIR_HINT} ${PC_RDKAFKA_INCLUDEDIR}
)

find_library(RDKAFKA_LIBRARY
  NAMES rdkafka
  HINTS ${RDKAFKA_LIBRARIES_DIR_HINT} ${PC_RDKAFKA_LIBDIR}
)

if (RDKAFKA_INCLUDE_DIR AND RDKAFKA_LIBRARY)
  set(HAVE_RDKAFKA TRUE)
  message(STATUS "librdkafka found: ${RDKAFKA_LIBRARY}")
endif()

if (NOT ENABLE_ALERT_KAFKA)
    message(STATUS "Kafka alerts are disabled. Disabling librdkafka support.")
    set(HAVE_RDKAFKA FALSE)
endif()

mark_as_advanced(
  RDKAFKA_INCLUDE_DIR
  RDKAFKA_LIBRARY
)