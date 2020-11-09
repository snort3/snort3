add_cpputest (payload_injector_test
  SOURCES
      ../payload_injector.cc
      ../payload_injector_module.cc
      ../../framework/module.cc
)

add_cpputest (payload_injector_translate_test
  SOURCES
      ../payload_injector_translate_page.cc
)
