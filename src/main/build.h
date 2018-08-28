#ifndef BUILD_H
#define BUILD_H

#include "utils/cpp_macros.h"

//-----------------------------------------------//
//     ____                   _                  //
//    / ___| _ __   ___  _ __| |_  _     _       //
//    \___ \| '_ \ / _ \| '__| __|| |_ _| |_     //
//     ___) | | | | (_) | |  | ||_   _|_   _|    //
//    |____/|_| |_|\___/|_|   \__||_|   |_|      //
//                                               //
//-----------------------------------------------//

#define BUILD_NUMBER 247

#ifndef EXTRABUILD
#define BUILD STRINGIFY_MX(BUILD_NUMBER)
#else
#define BUILD STRINGIFY_MX(PPCAT_MX(BUILD_NUMBER, EXTRABUILD))
#endif

#endif

