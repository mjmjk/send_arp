TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        header.cpp \
        main.cpp \
        parsing.cpp \
        pcapFunction.cpp \
        socket.cpp

HEADERS += \
    header.h \
    parsing.h \
    pcapFunction.h \
    pcapStruct.h \
    socket.h
LIBS += -lpcap
DISTFILES +=
