# Find the Unirec++ includes and library
#
# This module defines the following IMPORTED targets:
#
#  Unirec++::unirec++          - The "unirec++" library, if found.
#
# This module will set the following variables in your project:
#
#  UNIRECPLUSPLUS_INCLUDE_DIRS - where to find <unirec++/unirec.hpp>, etc.
#  UNIRECPLUSPLUS_LIBRARIES    - List of libraries when using unirec++.
#  UNIRECPLUSPLUS_FOUND        - True if the unirec++ library has been found.

# Use pkg-config (if available) to get the library directories and then use
# these values as hints for find_path() and find_library() functions.
find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
	pkg_check_modules(PC_UNIRECPLUSPLUS QUIET libunirec++)
endif()

find_path(
	UNIRECPLUSPLUS_INCLUDE_DIR unirec++
	HINTS ${PC_UNIRECPLUSPLUS_INCLUDEDIR} ${PC_UNIRECPLUSPLUS_INCLUDE_DIRS}
	PATH_SUFFIXES include
)

find_library(
	UNIRECPLUSPLUS_LIBRARY NAMES unirec++
	HINTS ${PC_UNIRECPLUSPLUS_LIBDIR} ${PC_UNIRECPLUSPLUS_LIBRARY_DIRS}
	PATH_SUFFIXES lib lib64
)

if (PC_UNIRECPLUSPLUS_VERSION)
	# Version extracted from pkg-config
	set(UNIRECPLUSPLUS_VERSION_STRING ${PC_UNIRECPLUSPLUS_VERSION})
endif()

# Handle find_package() arguments (i.e. QUIETLY and REQUIRED) and set
# UNIRECPLUSPLUS_FOUND to TRUE if all listed variables are filled.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
	UNIRECPLUSPLUS
	REQUIRED_VARS UNIRECPLUSPLUS_LIBRARY UNIRECPLUSPLUS_INCLUDE_DIR
	VERSION_VAR UNIRECPLUSPLUS_VERSION_STRING
)

set(UNIRECPLUSPLUS_INCLUDE_DIRS ${UNIRECPLUSPLUS_INCLUDE_DIR})
set(UNIRECPLUSPLUS_LIBRARIES ${UNIRECPLUSPLUS_LIBRARY})
mark_as_advanced(UNIRECPLUSPLUS_INCLUDE_DIR UNIRECPLUSPLUS_LIBRARY)

if (UNIRECPLUSPLUS_FOUND)
	# Create imported library with all dependencies
	if (NOT TARGET unirec++::unirec++ AND EXISTS "${UNIRECPLUSPLUS_LIBRARIES}")
		add_library(unirec++::unirec++ UNKNOWN IMPORTED)
		set_target_properties(unirec++::unirec++ PROPERTIES
			IMPORTED_LINK_INTERFACE_LANGUAGES "C"
			IMPORTED_LOCATION "${UNIRECPLUSPLUS_LIBRARIES}"
			INTERFACE_INCLUDE_DIRECTORIES "${UNIRECPLUSPLUS_INCLUDE_DIRS}")
	endif()
endif()
