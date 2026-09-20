QT += widgets

CONFIG += c++17

CONFIG(debug, debug|release) {
    LIBS += $$PWD/lib/PeaceDriverAPI_d.lib
} else {
    LIBS += $$PWD/lib/PeaceDriverAPI.lib
}


LIBS += Advapi32.lib \

SOURCES += \
    drv/DriverLoad.cpp \
    drv/Utils.cpp \
    main.cpp \
    mainwindow.cpp \
    msgfilterwindow.cpp

HEADERS += \
    drv/DriverLoad.h \
    drv/PeaceDriverAPI.h \
    drv/Utils.h \
    drv/sys.h \
    mainwindow.h \
    msgfilterwindow.h

FORMS += \
    mainwindow.ui \
    msgfilterwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
