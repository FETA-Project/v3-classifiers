# Find the CPPDST includes and library
#
# This module defines the following IMPORTED targets:
#
#  cppdst::dst          - The "cppdst" library, if found.
#
# This module will set the following variables in your project:
#
#  CPPDST_INCLUDE_DIRS - where to find headers.
#  CPPDST_LIBRARIES    - List of libraries when using cppdst.
#  CPPDST_FOUND        - True if the cppdst library has been found.

# Use pkg-config (if available) to get the library directories and then use
# these values as hints for find_path() and find_library() functions.
find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
	pkg_check_modules(PC_CPPDST QUIET cppdst)
endif()

find_path(
	CPPDST_INCLUDE_DIR dst
	HINTS ${PC_CPPDST_INCLUDEDIR} ${PC_CPPDST_INCLUDE_DIRS}
	PATH_SUFFIXES include
)

find_library(
	CPPDST_LIBRARY NAMES dst
	HINTS ${PC_CPPDST_LIBDIR} ${PC_CPPDST_LIBRARY_DIRS}
	PATH_SUFFIXES lib lib64
)

if (PC_CPPDST_VERSION)
	# Version extracted from pkg-config
	set(CPPDST_VERSION_STRING ${PC_CPPDST_VERSION})
endif()

# Handle find_package() arguments (i.e. QUIETLY and REQUIRED) and set
# CPPDST_FOUND to TRUE if all listed variables are filled.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
	CPPDST
	REQUIRED_VARS CPPDST_LIBRARY CPPDST_INCLUDE_DIR
	VERSION_VAR CPPDST_VERSION_STRING
)

set(CPPDST_INCLUDE_DIRS ${CPPDST_INCLUDE_DIR})
set(CPPDST_LIBRARIES ${CPPDST_LIBRARY})
mark_as_advanced(CPPDST_INCLUDE_DIR CPPDST_LIBRARY)

if (CPPDST_FOUND)
	# Create imported library with all dependencies
	if (NOT TARGET cppdst::dst AND EXISTS "${CPPDST_LIBRARIES}")
		add_library(cppdst::dst UNKNOWN IMPORTED)
		set_target_properties(cppdst::dst PROPERTIES
			IMPORTED_LINK_INTERFACE_LANGUAGES "C"
			IMPORTED_LOCATION "${CPPDST_LIBRARIES}"
			INTERFACE_INCLUDE_DIRECTORIES "${CPPDST_INCLUDE_DIRS}")
	endif()
endif()
