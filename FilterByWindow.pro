QT += widgets

RC_ICONS = assets/logo.ico

CONFIG += c++17

CONFIG(debug, debug|release) {
    LIBS += $$PWD/lib/PeaceDriverAPI_d.lib
} else {
    LIBS += $$PWD/lib/PeaceDriverAPI.lib
}

LIBS += Advapi32.lib \

SOURCES += \
    drv/PeaceDriverLoad.cpp \
    drv/Utils.cpp \
    main.cpp \
    mainwindow.cpp \
    msgfilterwindow.cpp \
    widgets/NeoPushButton.cpp

HEADERS += \
    drv/PeaceDriverAPI.h \
    drv/PeaceDriverLoad.h \
    drv/Utils.h \
    drv/sys.h \
    mainwindow.h \
    msgfilterwindow.h \
    widgets/NeoPushButton.h

INCLUDEPATH += $$PWD

FORMS += \
    mainwindow.ui \
    msgfilterwindow.ui

RESOURCES += resources.qrc

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
