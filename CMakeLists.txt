cmake_minimum_required(VERSION 3.12)
project(PSI-RELIC)

set(CMAKE_CXX_STANDARD 17)

# 통합된 컴파일러 플래그 설정
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -mtune=native -ggdb")

# OpenSSL 라이브러리 찾기
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# RELIC 라이브러리와 헤더 파일의 절대 경로 설정
set(RELIC_LIBRARY "/usr/local/lib/librelic_s.a")
set(RELIC_INCLUDE_DIR "/usr/local/include/relic")

# GMP 라이브러리 링크
set(GMP_LIBRARY "-lgmp")


add_executable(Semi_Honest_receiver src/Semi_Honest_receiver.cpp src/utils.cpp)
add_executable(Semi_Honest_sender src/Semi_Honest_sender.cpp src/utils.cpp)
add_executable(Malicious_receiver src/Malicious_receiver.cpp src/utils.cpp)
add_executable(Malicious_sender src/Malicious_sender.cpp src/utils.cpp)

# relic 및 OpenSSL 라이브러리 링크
target_link_libraries(Semi_Honest_receiver PUBLIC ${OPENSSL_LIBRARIES} ${RELIC_LIBRARY} ${GMP_LIBRARY} pthread)
target_link_libraries(Semi_Honest_sender PUBLIC ${OPENSSL_LIBRARIES} ${RELIC_LIBRARY} ${GMP_LIBRARY} pthread)
target_link_libraries(Malicious_receiver PUBLIC ${OPENSSL_LIBRARIES} ${RELIC_LIBRARY} ${GMP_LIBRARY} pthread)
target_link_libraries(Malicious_sender PUBLIC ${OPENSSL_LIBRARIES} ${RELIC_LIBRARY} ${GMP_LIBRARY} pthread)

# 타겟별로 include 경로 설정
target_include_directories(Semi_Honest_receiver PRIVATE ${RELIC_INCLUDE_DIR})
target_include_directories(Semi_Honest_sender PRIVATE ${RELIC_INCLUDE_DIR})
target_include_directories(Malicious_receiver PRIVATE ${RELIC_INCLUDE_DIR})
target_include_directories(Malicious_sender PRIVATE ${RELIC_INCLUDE_DIR})


# 실행 파일의 출력 디렉토리 설정
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# 추가 헤더 파일이 있는 디렉터리 포함
include_directories(include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# BLS12-381 설정
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

# BLS12-381 설정을 추가
foreach(option ${BLS12_381_SETTINGS})
    target_compile_definitions(Semi_Honest_receiver PRIVATE ${option})
    target_compile_definitions(Semi_Honest_sender PRIVATE ${option})
    target_compile_definitions(Malicious_receiver PRIVATE ${option})
    target_compile_definitions(Malicious_sender PRIVATE ${option})
endforeach()

# 새로운 옵션 설정
set(ADDITIONAL_OPTIONS
    TIMER=HREAL
    BN_PRECI=3072
    BENCH=1
    MULTI=PTHREAD
    EP_METHD "JACOB;LWNAF;COMBS;INTER"
)

# 새로운 옵션을 추가
foreach(option ${ADDITIONAL_OPTIONS})
    target_compile_definitions(Semi_Honest_receiver PRIVATE ${option})
    target_compile_definitions(Semi_Honest_sender PRIVATE ${option})
    target_compile_definitions(Malicious_receiver PRIVATE ${option})
    target_compile_definitions(Malicious_sender PRIVATE ${option})
endforeach()
