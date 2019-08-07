TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        all_pcap.cpp \
        header.cpp \
        main.cpp \
        parsing.cpp \
        pcap_msg.cpp \
        socket.cpp

HEADERS += \
    all_pcap.h \
    header.h \
    parsing.h \
    pcap_msg.h \
    socket.h

DISTFILES +=
