#include "Aliyun_MQTT_Signature.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    AliyunMQTTSignature window;

    window.show();

    return app.exec();
}
