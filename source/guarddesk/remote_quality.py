"""Local viewer defaults only. Never grants control or bypasses cohort checks."""
NATIVE='原生即時 · 內部預覽'
UNAVAILABLE='原生遠端元件尚未就緒'
FEATURES=('native_capture','native_input','webrtc_video','native_renderer')

def options(clarity,native,local_cohort,*,native_only=False):
    choices=['順暢 · 最高 8 FPS','省流量 · 最高 3 FPS']
    if clarity:choices.insert(0,'清晰 · 原始解析度／最高 2 FPS')
    compatible=(isinstance(local_cohort,str) and len(local_cohort)==64 and isinstance(native,dict)
        and native.get('wire')==1 and native.get('cohort_sha256')==local_cohort
        and all(feature in native.get('features',[]) for feature in FEATURES))
    if compatible:choices.insert(0,NATIVE)
    return [NATIVE] if native_only and compatible else [] if native_only else choices

def select(current,choices,*,manual=False):
    if not choices:return UNAVAILABLE
    if not manual and NATIVE in choices:return NATIVE
    return current if current in choices else choices[0]
