"""Bounded remote readiness metadata, shared by center and MIS viewer."""
REASONS = {
    'ready':'可連線',
    'no_desktop_report':'尚未收到登入桌面回報',
    'locked_or_disconnected':'桌面鎖定或工作階段已中斷',
    'multiple_interactive_sessions':'有多個互動桌面，請先確認協助對象',
    'elevated_context':'桌面元件未以標準權限執行',
    'disabled':'此端點未啟用遠端協助',
    'not_ready':'登入桌面尚未就緒',
}


def label(device):
    if (device.get('protocol') or 1)<2:return '需更新 Agent'
    if device.get('ready'):return REASONS['ready']
    return REASONS.get(device.get('readiness'),REASONS['not_ready'])
