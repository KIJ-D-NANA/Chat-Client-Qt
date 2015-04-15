#-------------------------------------------------
#
# Project created by QtCreator 2015-03-07T20:23:50
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Chat-Client-Qt
TEMPLATE = app
CONFIG += c++11
LIBS += -lcrypto

SOURCES += main.cpp\
        connectwindow.cpp \
    publicchat.cpp \
    privatechat.cpp \
    connection.cpp \
    chattextbox.cpp \
    rc4algorithm.cpp \
    rsaalgorithm.cpp

HEADERS  += connectwindow.h \
    publicchat.h \
    privatechat.h \
    connection.h \
    chattextbox.h \
    rc4algorithm.h \
    rsaalgorithm.h

FORMS    += connectwindow.ui \
    publicchat.ui \
    privatechat.ui
