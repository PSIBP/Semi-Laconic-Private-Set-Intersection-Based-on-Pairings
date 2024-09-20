cmake_minimum_required(VERSION 3.12)
project(PSI-RELIC)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -mtune=native -ggdb")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(RELIC_LIBRARY "/usr/local/lib/librelic_s.a")
set(RELIC_INCLUDE_DIR "/usr/local/include/relic")

set(GMP_LIBRARY "-lgmp")


add_executable(Semi_Honest_receiver src/Semi_Honest_receiver.cpp src/utils.cpp)
add_executable(Semi_Honest_sender src/Semi_Honest_sender.cpp src/utils.cpp)
add_executable(Malicious_receiver src/Malicious_receiver.cpp src/utils.cpp)
add_executable(Malicious_sender src/Malicious_sender.cpp src/utils.cpp)

target_link_libraries(Semi_Honest_receiver PUBLIC ${OPENSSL_LIBRARIES} ${RELIC_LIBRARY} ${GMP_LIBRARY} pthread)
target_link_libraries(Semi_Honest_sender PUBLIC ${OPENSSL_LIBRARIES} ${RELIC_LIBRARY} ${GMP_LIBRARY} pthread)
target_link_libraries(Malicious_receiver PUBLIC ${OPENSSL_LIBRARIES} ${RELIC_LIBRARY} ${GMP_LIBRARY} pthread)
target_link_libraries(Malicious_sender PUBLIC ${OPENSSL_LIBRARIES} ${RELIC_LIBRARY} ${GMP_LIBRARY} pthread)

target_include_directories(Semi_Honest_receiver PRIVATE ${RELIC_INCLUDE_DIR})
target_include_directories(Semi_Honest_sender PRIVATE ${RELIC_INCLUDE_DIR})
target_include_directories(Malicious_receiver PRIVATE ${RELIC_INCLUDE_DIR})
target_include_directories(Malicious_sender PRIVATE ${RELIC_INCLUDE_DIR})


set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

include_directories(include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(BLS12_381_SETTINGS
    WSIZE=64
    RAND=UDEV
    Semi_HonestLIB=OFF
    STBIN=ON
    # TIMER=CYCLE
    CHECK=off
    VERBS=off
    ARITH=x64-asm-6l
    FP_PRIME=381
    FP_METHD "INTEG;INTEG;INTEG;MONTY;LOWER;LOWER;SLIDE"
    FP_PMERS=off
    FP_QNRES=on
    FPX_METHD "INTEG;INTEG;LAZYR"
    EP_PLAIN=off
    EP_SUPER=off
    PP_METHD "LAZYR;OATEP"
)

foreach(option ${BLS12_381_SETTINGS})
    target_compile_definitions(Semi_Honest_receiver PRIVATE ${option})
    target_compile_definitions(Semi_Honest_sender PRIVATE ${option})
    target_compile_definitions(Malicious_receiver PRIVATE ${option})
    target_compile_definitions(Malicious_sender PRIVATE ${option})
endforeach()

set(ADDITIONAL_OPTIONS
    TIMER=HREAL
    BN_PRECI=3072
    BENCH=1
    MULTI=PTHREAD
    EP_METHD "JACOB;LWNAF;COMBS;INTER"
)

foreach(option ${ADDITIONAL_OPTIONS})
    target_compile_definitions(Semi_Honest_receiver PRIVATE ${option})
    target_compile_definitions(Semi_Honest_sender PRIVATE ${option})
    target_compile_definitions(Malicious_receiver PRIVATE ${option})
    target_compile_definitions(Malicious_sender PRIVATE ${option})
endforeach()
