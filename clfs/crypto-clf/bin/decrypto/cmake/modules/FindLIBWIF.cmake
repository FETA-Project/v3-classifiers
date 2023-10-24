# Find the WIF includes and library
#
# This module defines the following IMPORTED targets:
#
#  libwif::wif          - The "wif" library, if found.
#
# This module will set the following variables in your project:
#
#  LIBWIF_INCLUDE_DIRS - where to find headers.
#  LIBWIF_LIBRARIES    - List of libraries when using wif.
#  LIBWIF_FOUND        - True if the wif library has been found.

# Use pkg-config (if available) to get the library directories and then use
# these values as hints for find_path() and find_library() functions.
find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
	pkg_check_modules(PC_LIBWIF QUIET libwif)
endif()

find_path(
	LIBWIF_INCLUDE_DIR wif
	HINTS ${PC_LIBWIF_INCLUDEDIR} ${PC_LIBWIF_INCLUDE_DIRS}
	PATH_SUFFIXES include
)

find_library(
	LIBWIF_LIBRARY NAMES wif
	HINTS ${PC_LIBWIF_LIBDIR} ${PC_LIBWIF_LIBRARY_DIRS}
	PATH_SUFFIXES lib lib64
)

if (PC_LIBWIF_VERSION)
	# Version extracted from pkg-config
	set(LIBWIF_VERSION_STRING ${PC_LIBWIF_VERSION})
endif()

# Handle find_package() arguments (i.e. QUIETLY and REQUIRED) and set
# LIBWIF_FOUND to TRUE if all listed variables are filled.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
	LIBWIF
	REQUIRED_VARS LIBWIF_LIBRARY LIBWIF_INCLUDE_DIR
	VERSION_VAR LIBWIF_VERSION_STRING
)

set(LIBWIF_INCLUDE_DIRS ${LIBWIF_INCLUDE_DIR})
set(LIBWIF_LIBRARIES ${LIBWIF_LIBRARY})
mark_as_advanced(LIBWIF_INCLUDE_DIR LIBWIF_LIBRARY)

if (LIBWIF_FOUND)
	# Create imported library with all dependencies
	if (NOT TARGET libwif::wif AND EXISTS "${LIBWIF_LIBRARIES}")
		add_library(libwif::wif UNKNOWN IMPORTED)
		set_target_properties(libwif::wif PROPERTIES
			IMPORTED_LINK_INTERFACE_LANGUAGES "C"
			IMPORTED_LOCATION "${LIBWIF_LIBRARIES}"
			INTERFACE_INCLUDE_DIRECTORIES "${LIBWIF_INCLUDE_DIRS}")
	endif()
endif()
