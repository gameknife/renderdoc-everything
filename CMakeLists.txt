cmake_minimum_required(VERSION 3.16)
project(DLLWrapper)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable MASM
enable_language(ASM_MASM)

# Find all generated wrapper sets in wrapper directory
file(GLOB DEF_FILES "wrapper/*.def")

foreach(DEF_FILE ${DEF_FILES})
    # Extract DLL name from .def file
    get_filename_component(DLL_NAME ${DEF_FILE} NAME_WE)
    
    # Check if corresponding files exist
    set(CPP_FILE "wrapper/${DLL_NAME}_functions.cpp")
    set(ASM_FILE "wrapper/${DLL_NAME}_wrapper.asm")
    
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${CPP_FILE} AND 
       EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${ASM_FILE})
        
        message(STATUS "Building wrapper for ${DLL_NAME}")
        
        # Create the DLL target
        add_library(${DLL_NAME} SHARED
            ${CPP_FILE}
            ${ASM_FILE}
        )
        
        # Set the .def file for exports
        set_target_properties(${DLL_NAME} PROPERTIES
            LINK_FLAGS "/DEF:${DEF_FILE}"
            OUTPUT_NAME ${DLL_NAME}
            SUFFIX ".dll"
        )
        
        # Link required libraries
        target_link_libraries(${DLL_NAME} PRIVATE
            kernel32
            user32
        )
        
        # Set output directory to project root
        set_target_properties(${DLL_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}"
        )
        
    else()
        message(WARNING "Missing files for ${DLL_NAME}, skipping...")
    endif()
endforeach()
