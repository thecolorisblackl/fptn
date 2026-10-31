include(FetchContent)

# KCP (MIT): a single C file. Its own CMakeLists requires CMake 4, so build
# ikcp.c directly.
FetchContent_Declare(
  Kcp URL https://github.com/skywind3000/kcp/archive/b1a7a2101dcbb96017681a500d6b82bbe5a88766.zip)

FetchContent_GetProperties(Kcp)
if(NOT kcp_POPULATED)
  FetchContent_Populate(Kcp)
endif()

if(NOT TARGET fptn_kcp)
  enable_language(C)
  add_library(fptn_kcp STATIC "${kcp_SOURCE_DIR}/ikcp.c")
  set_target_properties(fptn_kcp PROPERTIES POSITION_INDEPENDENT_CODE ON)
  target_include_directories(fptn_kcp PUBLIC "${kcp_SOURCE_DIR}")
  if(MSVC)
    target_compile_options(fptn_kcp PRIVATE /W0)
  else()
    target_compile_options(fptn_kcp PRIVATE -w)
  endif()
endif()
