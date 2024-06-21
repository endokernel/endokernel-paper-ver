function(prepend_list set_to_var prefix_to_add)
    set(new_list "")
    foreach(item ${ARGN})
        list(APPEND new_list "${prefix_to_add}${item}")
    endforeach(item)
    set(${set_to_var} "${new_list}" PARENT_SCOPE)
endfunction(prepend_list)

function(append_list set_to_var suffix_to_add)
    set(new_list "")
    foreach(item ${ARGN})
        list(APPEND new_list "${item}${suffix_to_add}")
    endforeach(item)
    set(${set_to_var} "${new_list}" PARENT_SCOPE)
endfunction(append_list)

add_custom_target(
    distclean
    COMMAND ${CMAKE_COMMAND} -E remove_directory CMakeFiles
    COMMAND ${CMAKE_COMMAND} -E remove CMakeCache.txt
    COMMAND ${CMAKE_COMMAND} -E remove cmake_install.cmake
)
