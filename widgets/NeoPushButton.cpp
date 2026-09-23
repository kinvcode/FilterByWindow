#include "NeoPushButton.h"

namespace {

QString baseRules()
{
    return QStringLiteral(
        "NeoPushButton {"
        "  border: none;"
        "  border-radius: 14px;"
        "  padding: 10px 22px;"
        "  font-size: 14px;"
        "  font-weight: 600;"
        "  letter-spacing: 0.4px;"
        "}"
        "NeoPushButton:disabled {"
        "  color: #94a3b8;"
        "  background-color: #334155;"
        "  border: 1px solid #475569;"
        "}");
}

QString variantRules(NeoPushButton::Variant variant)
{
    switch (variant) {
    case NeoPushButton::Secondary:
        return QStringLiteral(
            "NeoPushButton {"
            "  color: #e2e8f0;"
            "  background-color: #1e293b;"
            "  border: 1px solid #475569;"
            "}"
            "NeoPushButton:hover {"
            "  color: #f8fafc;"
            "  background-color: #334155;"
            "  border: 1px solid #64748b;"
            "}"
            "NeoPushButton:pressed {"
            "  background-color: #0f172a;"
            "  border: 1px solid #475569;"
            "}");
    case NeoPushButton::Accent:
        return QStringLiteral(
            "NeoPushButton {"
            "  color: #042f2e;"
            "  background-color: qlineargradient("
            "    x1:0, y1:0, x2:1, y2:1,"
            "    stop:0 #2dd4bf, stop:1 #22d3ee);"
            "  border: 1px solid rgba(255, 255, 255, 0.35);"
            "}"
            "NeoPushButton:hover {"
            "  background-color: qlineargradient("
            "    x1:0, y1:0, x2:1, y2:1,"
            "    stop:0 #5eead4, stop:1 #67e8f9);"
            "}"
            "NeoPushButton:pressed {"
            "  background-color: qlineargradient("
            "    x1:0, y1:0, x2:1, y2:1,"
            "    stop:0 #14b8a6, stop:1 #06b6d4);"
            "}");
    case NeoPushButton::AccentDeep:
        return QStringLiteral(
            "NeoPushButton {"
            "  color: #ffffff;"
            "  background-color: #8BDEDA;"
            "  background-color: qlineargradient("
            "    x1:0, y1:0, x2:1, y2:0,"
            "    stop:0 #EF9393, stop:0.25 #E17DC2, stop:0.5 #998EE0,"
            "    stop:0.75 #43ADD0, stop:1 #8BDEDA);"
            "  border: 1px solid rgba(255, 255, 255, 0.45);"
            "}"
            "NeoPushButton:hover {"
            "  color: #ffffff;"
            "  background-color: qlineargradient("
            "    x1:0, y1:0, x2:1, y2:0,"
            "    stop:0 #F5ADAD, stop:0.25 #EE98D4, stop:0.5 #ADA3EE,"
            "    stop:0.75 #61C2E8, stop:1 #A8EBE7);"
            "  border: 1px solid rgba(255, 255, 255, 0.65);"
            "}"
            "NeoPushButton:pressed {"
            "  color: #f8fafc;"
            "  background-color: qlineargradient("
            "    x1:0, y1:0, x2:1, y2:0,"
            "    stop:0 #D97A7A, stop:0.25 #C868AE, stop:0.5 #887FD0,"
            "    stop:0.75 #3599BC, stop:1 #76C8C4);"
            "  border: 1px solid rgba(255, 255, 255, 0.25);"
            "  padding-top: 11px;"
            "  padding-bottom: 9px;"
            "}");
    case NeoPushButton::Danger:
        return QStringLiteral(
            "NeoPushButton {"
            "  color: #ffffff;"
            "  background-color: qlineargradient("
            "    x1:0, y1:0, x2:1, y2:1,"
            "    stop:0 #fb7185, stop:1 #f43f5e);"
            "  border: 1px solid rgba(255, 255, 255, 0.22);"
            "}"
            "NeoPushButton:hover {"
            "  background-color: qlineargradient("
            "    x1:0, y1:0, x2:1, y2:1,"
            "    stop:0 #fda4af, stop:1 #fb7185);"
            "}"
            "NeoPushButton:pressed {"
            "  background-color: qlineargradient("
            "    x1:0, y1:0, x2:1, y2:1,"
            "    stop:0 #e11d48, stop:1 #be123c);"
            "}");
    case NeoPushButton::Ghost:
        return QStringLiteral(
            "NeoPushButton {"
            "  color: #38bdf8;"
            "  background-color: rgba(15, 23, 42, 0.35);"
            "  border: 1px solid #38bdf8;"
            "}"
            "NeoPushButton:hover {"
            "  color: #e0f2fe;"
            "  background-color: rgba(56, 189, 248, 0.18);"
            "  border: 1px solid #7dd3fc;"
            "}"
            "NeoPushButton:pressed {"
            "  color: #bae6fd;"
            "  background-color: rgba(56, 189, 248, 0.28);"
            "}");
    case NeoPushButton::Primary:
    default:
        return QStringLiteral(
            "NeoPushButton {"
            "  color: #ffffff;"
            "  background-color: qlineargradient("
            "    x1:0, y1:0, x2:1, y2:1,"
            "    stop:0 #6366f1, stop:1 #8b5cf6);"
            "  border: 1px solid rgba(255, 255, 255, 0.25);"
            "}"
            "NeoPushButton:hover {"
            "  background-color: qlineargradient("
            "    x1:0, y1:0, x2:1, y2:1,"
            "    stop:0 #818cf8, stop:1 #a78bfa);"
            "}"
            "NeoPushButton:pressed {"
            "  background-color: qlineargradient("
            "    x1:0, y1:0, x2:1, y2:1,"
            "    stop:0 #4f46e5, stop:1 #7c3aed);"
            "}");
    }
}

} // namespace

NeoPushButton::NeoPushButton(QWidget* parent)
    : QPushButton(parent)
{
    setCursor(Qt::PointingHandCursor);
    setFocusPolicy(Qt::StrongFocus);
    applyStyle();
}

NeoPushButton::NeoPushButton(const QString& text, QWidget* parent)
    : NeoPushButton(parent)
{
    setText(text);
}

void NeoPushButton::setVariant(Variant variant)
{
    if (m_variant == variant) {
        return;
    }
    m_variant = variant;
    applyStyle();
    emit variantChanged(m_variant);
}

void NeoPushButton::applyStyle()
{
    setStyleSheet(baseRules() + variantRules(m_variant));
}
