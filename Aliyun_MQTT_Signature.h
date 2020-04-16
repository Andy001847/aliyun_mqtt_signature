#ifndef ALIYUNMQTTSIGNATURE_H
#define ALIYUNMQTTSIGNATURE_H

#include <QMainWindow>
#include <QDebug>
#include <QCryptographicHash>
#include <QByteArray>
#include <QMessageBox>

typedef enum error_code
{
    ERR_OK                        = 0x00,
    ERR_INSTANCE_ID_IS_NULL       = 0x01,
    ERR_GROUP_ID_IS_NULL          = 0x01,
    ERR_DEVICE_ID_IS_NULL         = 0x02,
    ERR_ACCESS_KEY_IS_NULL        = 0x03,
    ERR_ACCESS_KEY_SECRET_IS_NULL = 0x04,
}error_code_t;

QT_BEGIN_NAMESPACE
namespace Ui { class AliyunMQTTSignature; }
QT_END_NAMESPACE

class AliyunMQTTSignature : public QMainWindow
{
    Q_OBJECT

public:
    AliyunMQTTSignature(QWidget *parent = nullptr);
    ~AliyunMQTTSignature();

    QByteArray hmac_sha1(QByteArray key, QByteArray data);

public slots:
    error_code_t calculate_signature(void);

private:
    Ui::AliyunMQTTSignature *ui;
    QByteArray hmac_sha1_data;
};
#endif // ALIYUNMQTTSIGNATURE_H
