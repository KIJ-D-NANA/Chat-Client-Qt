#ifndef CONNECTWINDOW_H
#define CONNECTWINDOW_H

#include <QMainWindow>

namespace Ui {
class ConnectWindow;
}

class ConnectWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit ConnectWindow(QWidget *parent = 0);
    ~ConnectWindow();

private:
    Ui::ConnectWindow *ui;
    const char* CA = "-----BEGIN PUBLIC KEY-----\n"
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6rGjca3LW4dmTkiKTH+0\n"
            "DvYwcRCAyFm1YaQlJVFgJvc5NqTBF2Kvud0MjvJuqhMPKSkP/V+P9cm3cJsnv2Fm\n"
            "NC43KGWDw7P2laGvrTbVmisJXN3JnuguuxGmhEFau68im/etHH6YWICfcnEoKcbs\n"
            "RuSmg9zR7N/mnf3BxZMc6oUW8sH1XCxe5AqLdZuYNoWdLGECtvghwGWUH3hEAvFL\n"
            "D5qXp2TOz/53iDJNfDoZWTmUHEFCR2XP9lS52nTYobZl/9aHhm3vM61cQBvLQ1VH\n"
            "lCIxhpR6TZGPJdbrneqCZcvNZD5lieQXcFeJUgp/5olDA07e6O7ifoDloKjrW8Xj\n"
            "UhD1PQLNlV426D6ugRAb/uhMFFWMVUhxcN6d1Y+pXvcCuC63R6fAw1J8KaQxZJhG\n"
            "jxwmA25si7xnbgr4UyFkwO+sij0NcYG1DwYU4xMHENYWoKwVk+dGQGrhyNP/RcWa\n"
            "siPqLcJ8jzFg0l0Wd6aDCou0etj9/MeUlaZhs+IiHQ30oHPR7f+TzgKPoSTEX4Oi\n"
            "F4xKJddb8Du3KsRe+0HehEkoww13bLVyu2DBKk5mjZ3G7G2jcfYKrTxvxYspZPUF\n"
            "YtHnorxpRLDKo11oJwfhAZyP3CIj1UxvUjUdWTJA3PBXyKlx8XjuWIq7Bp7D1IM2\n"
            "hhqoeUQRoLEHPdJKzElOs2UCAwEAAQ==\n"
            "-----END PUBLIC KEY-----";

public slots:
    void ConnectToHost();
};

#endif // CONNECTWINDOW_H
