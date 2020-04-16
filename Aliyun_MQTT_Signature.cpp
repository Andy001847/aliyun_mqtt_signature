#include "Aliyun_MQTT_Signature.h"
#include "ui_Aliyun_MQTT_Signature.h"

AliyunMQTTSignature::AliyunMQTTSignature(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::AliyunMQTTSignature)
{
    ui->setupUi(this);

    /* 设置窗口标题 */
    this->setWindowTitle(QString("阿里云MQTT签名校验工具"));

    /* 固定窗口的大小，防止拖拽变形 */
    this->setMinimumSize(QSize(800, 550));
    this->setMaximumSize(QSize(800, 550));

    connect(ui->Calculate_signature_pushButton, &QPushButton::clicked, this, &AliyunMQTTSignature::calculate_signature);
}

AliyunMQTTSignature::~AliyunMQTTSignature()
{
    delete ui;
}

QByteArray AliyunMQTTSignature::hmac_sha1(QByteArray key, QByteArray data)
{
    int block_size = 64;    /* HMAC_SHA1标准块的大小为64字节 */
    if(key.length() > block_size)
    {
        key = QCryptographicHash::hash(key, QCryptographicHash::Sha1);
    }

    QByteArray inner_padding(block_size, char(0x36));
    QByteArray outer_padding(block_size, char(0x5C));

    int key_index = 0;
    for(key_index = 0; key_index < key.length(); key_index++)
    {
        inner_padding[key_index] = inner_padding[key_index] ^ key.at(key_index);
        outer_padding[key_index] = outer_padding[key_index] ^ key.at(key_index);
    }

    QByteArray part = inner_padding;
    part.append(data);

    QByteArray total = outer_padding;
    total.append(QCryptographicHash::hash(part, QCryptographicHash::Sha1));

    QByteArray hashed = QCryptographicHash::hash(total, QCryptographicHash::Sha1);

    return hashed;
}

error_code_t AliyunMQTTSignature::calculate_signature(void)
{
    QString instance_id = ui->Instance_ID_lineEdit->text();
    if(instance_id.isEmpty())
    {
        QMessageBox::warning(NULL, "警告", "请填写Instance ID的内容！");

        return ERR_INSTANCE_ID_IS_NULL;
    }

    QString group_id = ui->Group_ID_lineEdit->text();
    if(group_id.isEmpty())
    {
        QMessageBox::warning(NULL, "警告", "请填写Group ID的内容！");

        return ERR_GROUP_ID_IS_NULL;
    }

    QString device_id = ui->Device_ID_lineEdit->text();
    if(device_id.isEmpty())
    {
        QMessageBox::warning(NULL, "警告", "请填写Device ID的内容！");

        return ERR_DEVICE_ID_IS_NULL;
    }

    QString access_key = ui->Access_Key_ID_lineEdit->text();
    if(access_key.isEmpty())
    {
        QMessageBox::warning(NULL, "警告", "请填写Access Key ID的内容！");

        return ERR_ACCESS_KEY_IS_NULL;
    }

    QString access_key_secret = ui->Access_Key_Secret_lineEdit->text();
    if(access_key_secret.isEmpty())
    {
        QMessageBox::warning(NULL, "警告", "请填写Access Key Secret的内容！");

        return ERR_ACCESS_KEY_SECRET_IS_NULL;
    }

    /* 计算MQTT Cleint ID */
    QString mqtt_client_id = ui->Group_ID_lineEdit->text();
    mqtt_client_id.append("@@@");
    mqtt_client_id.append(ui->Device_ID_lineEdit->text());

    ui->MQTT_Cleint_ID_lineEdit->setText(mqtt_client_id);

    /* 计算用户名 */
    QString username = "Signature|";

    username.append(access_key);
    username.append("|");
    username.append(instance_id);

    ui->Username_lineEdit->setText(username);

    /* 计算密码 */
    QByteArray hmac_sha1_password = hmac_sha1(access_key_secret.toLatin1(), mqtt_client_id.toLatin1());
    QByteArray base64_password = hmac_sha1_password.toBase64();

    QString password;
    password.prepend(base64_password);

    ui->Password_lineEdit->setText(password);

    return ERR_OK;
}
