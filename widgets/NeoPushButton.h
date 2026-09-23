#ifndef NEOPUSHBUTTON_H
#define NEOPUSHBUTTON_H

#include <QPushButton>

class NeoPushButton : public QPushButton
{
    Q_OBJECT
    Q_PROPERTY(Variant variant READ variant WRITE setVariant NOTIFY variantChanged)

public:
    enum Variant {
        Accent = 0,
        AccentDeep,
        Secondary,
        Primary,
        Danger,
        Ghost
    };
    Q_ENUM(Variant)

    explicit NeoPushButton(QWidget* parent = nullptr);
    explicit NeoPushButton(const QString& text, QWidget* parent = nullptr);

    Variant variant() const { return m_variant; }
    void setVariant(Variant variant);

signals:
    void variantChanged(Variant variant);

private:
    void applyStyle();

    Variant m_variant = Primary;
};

#endif // NEOPUSHBUTTON_H
