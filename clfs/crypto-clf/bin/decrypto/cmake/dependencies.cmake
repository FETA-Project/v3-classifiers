# Project dependencies
find_package(UNIREC REQUIRED)
find_package(LIBTRAP REQUIRED)
find_package(UNIRECPLUSPLUS REQUIRED)
find_package(CPPDST REQUIRED)
find_package(LIBWIF REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Development NumPy)
find_package(Threads REQUIRED)

# Set define for none depricated API for NUMPY
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNPY_NO_DEPRECATED_API=NPY_1_7_API_VERSION")
