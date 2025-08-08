# DTLSv13 CMake Config File

####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was DTLSv13Config.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

macro(check_required_components _NAME)
  foreach(comp ${${_NAME}_FIND_COMPONENTS})
    if(NOT ${_NAME}_${comp}_FOUND)
      if(${_NAME}_FIND_REQUIRED_${comp})
        set(${_NAME}_FOUND FALSE)
      endif()
    endif()
  endforeach()
endmacro()

####################################################################################

# Find dependencies
find_dependency(Threads)

# Optional dependencies
find_dependency(OpenSSL QUIET)
find_dependency(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(BOTAN QUIET botan-3)
endif()

# Include the targets file
include("${CMAKE_CURRENT_LIST_DIR}/DTLSv13Targets.cmake")

# Set component variables for backwards compatibility
set(DTLSv13_CRYPTO_FOUND TRUE)
set(DTLSv13_TRANSPORT_FOUND TRUE)
set(DTLSv13_PROTOCOL_FOUND TRUE)

# Version information
set(DTLSv13_VERSION_MAJOR 1)
set(DTLSv13_VERSION_MINOR 0)
set(DTLSv13_VERSION_PATCH 0)
set(DTLSv13_VERSION 1.0.0)

# Check for required components
check_required_components(DTLSv13)

# Set legacy variables for backwards compatibility
if(TARGET DTLSv13::dtlsv13)
    get_target_property(DTLSv13_INCLUDE_DIRS DTLSv13::dtlsv13 INTERFACE_INCLUDE_DIRECTORIES)
    get_target_property(DTLSv13_LIBRARIES DTLSv13::dtlsv13 LOCATION)
    set(DTLSv13_FOUND TRUE)
endif()
