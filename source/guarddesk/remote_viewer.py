"""Native Windows MIS viewer. Tk owns every widget; workers own transport only."""
import argparse
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk

from .remote_client import RemoteClient, ViewerEngine, viewport, pointer
from .remote_codec import KEYS


class RemoteViewer:
    def __init__(self,root,server='http://127.0.0.1:8788',*,workstation=False,ca=None,tray=False):
        self.tk,self.ttk,self.root=tk,ttk,root
        self.client=None;self.engine=None;self.username='';self.catalog_data={};self.devices=[]
        self.tray=None;self.hidden=False
        self.native_root=None;self.native_cohort=None
        try:
            from .mis_onefile import native_media_root
            self.native_root=native_media_root()
            if self.native_root:
                from .remote_components import read_cohort
                self.native_cohort=read_cohort(self.native_root,role='mis')['build_id']
        except (OSError,ValueError):pass
        self.tray_actions=queue.Queue(16)
        self.workstation=workstation;self.ca=tk.StringVar(value=ca or '')
        self.jobs=queue.Queue(16);self.busy=False;self.closing=threading.Event()
        self.image=None;self.photo=None;self.rect=(0,0,1,1);self.last_point={'x':.5,'y':.5};self.fullscreen=False
        self.resize_job=None;self.finished=False
        self.fullscreen_layout=[];self.toolbar_job=None;self.frame_codec=''
        root.title('GuardDesk 遠端協助');root.geometry('1280x860');root.minsize(900,640)
        root.configure(bg='#f3f6f8');root.protocol('WM_DELETE_WINDOW',self.window_close)
        style=ttk.Style(root)
        if 'vista' in style.theme_names():style.theme_use('vista')
        style.configure('TLabel',font=('Microsoft JhengHei UI',10),background='#f3f6f8')
        style.configure('TButton',font=('Microsoft JhengHei UI',10),padding=(12,7))
        style.configure('TFrame',background='#f3f6f8')
        style.configure('TEntry',padding=5)
        self.status=tk.StringVar(value='請以 MIS／授權支援帳號登入公司 Server' if workstation else '請以 MIS／授權支援帳號登入 Server 本機管理中心')
        self.server=tk.StringVar(value=server);self.user=tk.StringVar();self.password=tk.StringVar()
        self.device=tk.StringVar();self.mode=tk.StringVar(value='僅檢視');self.quality=tk.StringVar(value='清晰 · 原始解析度／最高 2 FPS')
        self.display=tk.StringVar(value='符合視窗')
        self.reason=tk.StringVar();self.metric=tk.StringVar(value='未連線')
        self.header=tk.Frame(root,bg='#15353d',height=68);self.header.pack(fill='x');self.header.pack_propagate(False)
        tk.Label(self.header,text='G',bg='#1e5960',fg='white',font=('Segoe UI',20,'bold'),padx=13,pady=5).pack(side='left',padx=(22,12),pady=10)
        tk.Label(self.header,text='GuardDesk  遠端協助',bg='#15353d',fg='white',font=('Microsoft JhengHei UI',15,'bold')).pack(side='left')
        tk.Label(self.header,text='Windows 桌面程式',bg='#15353d',fg='#a7c7cc',font=('Microsoft JhengHei UI',10)).pack(side='right',padx=24)
        self.body=ttk.Frame(root,padding=22);self.body.pack(fill='both',expand=True)
        self.footer=ttk.Label(root,textvariable=self.status,padding=(22,12),wraplength=1200);self.footer.pack(fill='x')
        self.login_screen()
        if tray:
            try:
                from .remote_tray import TrayIcon
                self.tray=TrayIcon(lambda action:self.tray_actions.put_nowait(action),self.show_from_tray,self.stop_session,self.close)
                ttk.Button(self.header,text='縮至通知區',command=self.window_close).pack(side='right',padx=12)
                self.status.set('關閉視窗會縮至右下角通知區；右鍵圖示可完全結束。協助中縮小會先停止連線。')
            except OSError:self.status.set('無法建立通知區圖示，關閉視窗會結束程式。')
        root.bind('<Control-Alt-Shift-F12>',lambda event:self.toggle_fullscreen())
        root.bind('<FocusOut>',self.focus_out,add='+')
        root.after(30,self.tick);root.after(5000,self.auto_refresh)

    def reset_body(self):
        for widget in self.body.winfo_children():widget.destroy()

    def login_screen(self):
        self.reset_body()
        box=ttk.Frame(self.body,padding=32);box.place(relx=.5,rely=.42,anchor='center')
        ttk.Label(box,text='登入遠端協助',font=('Microsoft JhengHei UI',22,'bold')).grid(row=0,column=0,columnspan=2,sticky='w',pady=(0,12))
        ttk.Label(box,text='MIS 工作站透過 HTTPS 連回公司 Server；每次仍須使用者同意。' if self.workstation else '在 Server 本機執行；端點每次仍須同意連線。').grid(row=1,column=0,columnspan=2,sticky='w',pady=(0,22))
        for row,label,var,secret in [(2,'管理中心',self.server,False),(3,'MIS／支援帳號',self.user,False),(4,'密碼',self.password,True)]:
            ttk.Label(box,text=label).grid(row=row,column=0,sticky='w',padx=(0,20),pady=8)
            entry=ttk.Entry(box,textvariable=var,width=36,show='●' if secret else '')
            entry.grid(row=row,column=1,sticky='ew',pady=8)
            if secret:entry.bind('<Return>',lambda event:self.login())
        row=5
        if self.workstation:
            ttk.Label(box,text='CA 憑證檔（選填）').grid(row=row,column=0,sticky='w',padx=(0,20),pady=8)
            ttk.Entry(box,textvariable=self.ca,width=36).grid(row=row,column=1,sticky='ew',pady=8)
            row+=1
            ttk.Label(box,text='使用公司提供的 CA；留白使用 Windows／Python 預設信任。不跳過憑證驗證。',wraplength=540).grid(row=row,column=0,columnspan=2,sticky='w');row+=1
        self.login_button=ttk.Button(box,text='登入',command=self.login)
        self.login_button.grid(row=row,column=1,sticky='ew',pady=(18,10))
        ttk.Label(box,text='密碼及登入憑證只保留於本次程式記憶體，不存檔。',foreground='#647780').grid(row=row+1,column=0,columnspan=2,sticky='w',pady=8)

    def background(self,work,done):
        if self.busy or self.closing.is_set():return False
        self.busy=True
        def run():
            try:result,error=work(),None
            except (OSError,ValueError,KeyError) as exc:result,error=None,str(exc)[:300]
            self.jobs.put((done,result,error))
        threading.Thread(target=run,name='GuardDesk desktop request',daemon=True).start()
        return True

    def login(self):
        if self.busy:return
        username=self.user.get().strip();password=self.password.get();server=self.server.get()
        workstation=self.workstation;ca=self.ca.get().strip() or None
        if not username or not password:self.status.set('請填寫帳號與密碼');return
        if len(username)>80 or len(password)>1024:self.status.set('帳號或密碼長度不正確');return
        self.password.set('');self.login_button.configure(state='disabled');self.status.set('登入中…')
        def work():
            client=RemoteClient(server,workstation=workstation,ca=ca);catalog=client.login(username,password)
            if self.closing.is_set():client.logout();return None
            return client,catalog
        def done(result,error):
            if error:self.login_button.configure(state='normal');self.status.set(error);return
            self.client,self.catalog_data=result;self.username=username;self.workspace()
        self.background(work,done)

    def workspace(self):
        self.reset_body()
        self.quality_manual=False;self.quality_device=None
        top=ttk.Frame(self.body);top.pack(fill='x',pady=(0,14))
        ttk.Label(top,text='選擇已授權端點',font=('Microsoft JhengHei UI',17,'bold')).pack(side='left')
        ttk.Button(top,text='登出',command=self.logout).pack(side='right')
        ttk.Label(top,text=self.username+'  ·  '+self.client.server,foreground='#647780').pack(side='right',padx=20)
        controls=ttk.Frame(self.body);controls.pack(fill='x')
        for column,text in enumerate(['端點','操作模式','傳輸模式','協助原因（選填）']):ttk.Label(controls,text=text).grid(row=0,column=column,sticky='w',padx=(0,10))
        self.device_box=ttk.Combobox(controls,textvariable=self.device,state='readonly',width=29)
        self.device_box.grid(row=1,column=0,sticky='ew',padx=(0,12),pady=(6,12));self.device_box.bind('<<ComboboxSelected>>',lambda event:self.selection_changed())
        self.mode_box=ttk.Combobox(controls,textvariable=self.mode,state='readonly',values=['僅檢視','檢視並控制'],width=14);self.mode_box.grid(row=1,column=1,padx=(0,12))
        choices=['順暢 · 最高 8 FPS','省流量 · 最高 3 FPS']
        if self.catalog_data.get('clarity_protocol',0)>=3:choices.insert(0,'清晰 · 原始解析度／最高 2 FPS')
        if self.quality.get() not in choices:self.quality.set(choices[0])
        self.quality_box=ttk.Combobox(controls,textvariable=self.quality,state='readonly',values=choices,width=29)
        self.quality_box.bind('<<ComboboxSelected>>',lambda event:setattr(self,'quality_manual',True))
        self.quality_box.grid(row=1,column=2,padx=(0,12))
        ttk.Entry(controls,textvariable=self.reason,width=26).grid(row=1,column=3,sticky='ew');controls.columnconfigure(3,weight=1)
        actions=ttk.Frame(self.body);actions.pack(fill='x',pady=(0,12))
        self.connect_button=ttk.Button(actions,text='要求使用者確認',command=self.request);self.connect_button.pack(side='left')
        self.stop_button=ttk.Button(actions,text='停止協助',command=self.stop_session,state='disabled');self.stop_button.pack(side='left',padx=10)
        self.refresh_button=ttk.Button(actions,text='更新端點狀態',command=self.refresh);self.refresh_button.pack(side='left')
        self.fullscreen_button=ttk.Button(actions,text='全螢幕／還原',command=self.toggle_fullscreen);self.fullscreen_button.pack(side='right')
        self.native_actions=ttk.Frame(self.body)
        self.native_window_button=ttk.Button(self.native_actions,text='操作遠端視窗',command=self.activate_native_window,state='disabled');self.native_window_button.pack(side='left')
        ttk.Button(self.native_actions,text='輸入診斷',command=self.show_native_diagnostics).pack(side='right')
        ttk.Label(self.native_actions,text='鍵盤與滑鼠請在獨立影像視窗內操作；也可使用右上方「放大操作視窗／還原」。',wraplength=600).pack(side='left',padx=12)
        self.display_box=ttk.Combobox(actions,textvariable=self.display,state='readonly',values=['符合視窗','100% 原始大小'],width=16)
        self.display_box.pack(side='right',padx=10);self.display_box.bind('<<ComboboxSelected>>',self.display_changed)
        ttk.Label(actions,textvariable=self.metric,foreground='#647780').pack(side='right',padx=18)
        self.screen=ttk.Frame(self.body);self.screen.pack(fill='both',expand=True)
        self.screen.rowconfigure(0,weight=1);self.screen.columnconfigure(0,weight=1)
        self.canvas=self.tk.Canvas(self.screen,bg='#13252d',highlightthickness=0,takefocus=True)
        self.canvas.grid(row=0,column=0,sticky='nsew')
        self.hscroll=ttk.Scrollbar(self.screen,orient='horizontal',command=self.canvas.xview)
        self.vscroll=ttk.Scrollbar(self.screen,orient='vertical',command=self.canvas.yview)
        self.canvas.configure(xscrollcommand=self.hscroll.set,yscrollcommand=self.vscroll.set)
        self.fullbar=ttk.Frame(self.screen,padding=(8,3))
        ttk.Button(self.fullbar,text='還原視窗',command=self.toggle_fullscreen).pack(side='left')
        ttk.Button(self.fullbar,text='停止協助',command=self.stop_session).pack(side='left',padx=6)
        ttk.Button(self.fullbar,text='符合／100%',command=self.toggle_display).pack(side='left')
        ttk.Label(self.fullbar,textvariable=self.metric).pack(side='left',padx=10)
        self.fullbar.bind('<Leave>',lambda event:self.schedule_toolbar_hide())
        self.screen_item=self.canvas.create_image(0,0,anchor='nw')
        self.message_item=self.canvas.create_text(20,20,anchor='nw',text='選擇端點並要求使用者確認後，才會顯示畫面。',fill='#d8e7eb',font=('Microsoft JhengHei UI',13))
        self.canvas.bind('<Configure>',self.resize)
        self.canvas.bind('<Motion>',self.motion)
        for button in (1,2,3):
            self.canvas.bind('<ButtonPress-'+str(button)+'>',lambda event,n=button:self.button(event,n,True))
            self.canvas.bind('<ButtonRelease-'+str(button)+'>',lambda event,n=button:self.button(event,n,False))
        self.canvas.bind('<MouseWheel>',self.wheel)
        self.canvas.bind('<KeyPress>',lambda event:self.key(event,True));self.canvas.bind('<KeyRelease>',lambda event:self.key(event,False))
        ttk.Label(self.body,text='版本相符的新版端點預設原生即時，請在獨立影像視窗操作；可按「操作遠端視窗」帶起。清晰模式保留原解析度（最高 4K），更新較慢。\n原生一般協助遇 UAC 暫停；管理員協助經授權與同意後可操作 UAC。舊傳輸的一般協助遇 UAC 會結束。\nCtrl+Alt+Shift+F12 切換放大／還原。原生協助持續至停止或授權中止；鎖定／登出都停止。舊圖片傳輸仍最長 10 分鐘。',foreground='#647780').pack(fill='x',pady=(10,0))
        self.display_changed();self.update_devices();self.status.set('僅顯示此帳號已取得單台或全部端點授權的端點；每次連線仍須使用者同意。')

    def update_devices(self):
        grants={g['device_id']:g for g in self.catalog_data.get('grants',[]) if g['username']==self.username and g['expires']>time.time()}
        self.devices=[{**d,'grant':grants[d['id']]} for d in self.catalog_data.get('devices',[]) if d['id'] in grants]
        from .remote_readiness import label
        labels=[d['name']+' · '+label(d) for d in self.devices]
        selected=self.device_box.current();self.device_box.configure(values=labels)
        if labels:self.device_box.current(min(max(0,selected),len(labels)-1))
        else:self.device.set('沒有已授權端點')
        self.selection_changed()

    def selection_changed(self):
        index=self.device_box.current();d=self.devices[index] if 0<=index<len(self.devices) else None
        allowed=['僅檢視','檢視並控制'] if d and d['grant']['can_control'] else ['僅檢視']
        if d and d['grant'].get('can_elevate') and (d.get('protocol') or 1)>=6 and self.catalog_data.get('admin_protocol',0)>=6:
            allowed.append('管理員協助（含 UAC）')
        self.mode_box.configure(values=allowed)
        if self.mode.get() not in allowed:self.mode.set('僅檢視')
        native_only=self.catalog_data.get('native_only_trial') is True
        from .remote_quality import options,select
        did=d.get('id') if d else None
        if did!=getattr(self,'quality_device',None):self.quality_device=did;self.quality_manual=False
        choices=options(self.catalog_data.get('clarity_protocol',0)>=3,d.get('native') if d else None,
            getattr(self,'native_cohort',None) if self.native_root else None,native_only=native_only)
        self.quality_box.configure(values=choices)
        self.quality.set(select(self.quality.get(),choices,manual=getattr(self,'quality_manual',False)))
        ready=bool(d and d['ready'] and (d.get('protocol') or 1)>=2 and (not native_only or choices))
        self.connect_button.configure(state='normal' if ready and self.engine is None and not self.busy else 'disabled')
        if d and not ready and self.engine is None and not self.busy:
            from .remote_readiness import label
            self.status.set('遠端未就緒：'+label(d)+'。電腦上線不代表登入桌面已回報。')

    def refresh(self):
        if not self.client or self.engine or self.busy:return
        def done(result,error):
            if error:self.status.set(error);return
            self.catalog_data=result;self.update_devices()
        self.background(self.client.catalog,done)

    def auto_refresh(self):
        if self.closing.is_set():return
        self.refresh();self.root.after(30000 if self.hidden else 5000,self.auto_refresh)

    def request(self):
        if self.engine or self.busy:return
        index=self.device_box.current()
        if not 0<=index<len(self.devices):return
        reason=self.reason.get().strip()
        if len(reason)>200 or any(ord(c)<32 for c in reason):self.status.set('協助原因最多 200 字，可留空');return
        d=self.devices[index];admin_control=self.mode.get()=='管理員協助（含 UAC）';mode='control' if admin_control or self.mode.get()=='檢視並控制' else 'view'
        native=self.quality.get().startswith('原生即時')
        if native and (not self.native_root or not d.get('native') or (admin_control and not d['native'].get('secure_desktop'))):
            self.status.set('此原生元件尚未提供所選協助能力，請重新選擇模式。');return
        quality='clarity' if self.quality.get().startswith('清晰') else 'economy' if self.quality.get().startswith('省流量') else 'balanced'
        self.connect_button.configure(state='disabled');self.status.set('正在要求端點使用者確認…')
        client=self.client
        def work():
            if native:
                from .remote_components import read_cohort
                cohort=read_cohort(self.native_root,role='mis')
                session=client.call('/api/remote/request',{'device_id':d['id'],'mode':mode,'reason':reason,'viewer':'desktop',
                    'quality':'balanced','transport':'native_webrtc','native_wire':1,'native_cohort_sha256':cohort['build_id'],
                    **({'admin_control':True,'admin_wire':6} if admin_control else {})})
            else:session=client.request(d['id'],mode,reason,quality,**({'admin_control':True} if admin_control else {}))
            if self.closing.is_set():client.call('/api/remote/stop',{'session_id':session['id']});return None
            return session
        def done(result,error):
            if error:self.status.set(error);self.selection_changed();return
            self.finished=False
            if native:
                if self.fullscreen:self._toggle_canvas_fullscreen()
                from .mis_native_media import NativeViewerEngine
                self.engine=NativeViewerEngine(client,result,self.native_root)
            else:self.engine=ViewerEngine(client,result)
            try:self.engine.start()
            except (OSError,RuntimeError,ValueError):
                self.engine.stop();self.engine=None
                self.status.set('原生工作仍在結束，暫時無法建立新的協助。')
                self.selection_changed()
                self.background(lambda:client.call('/api/remote/stop',{'session_id':result['id']}),lambda _result,_error:self.selection_changed())
                return
            self.device_box.configure(state='disabled');self.mode_box.configure(state='disabled')
            self.quality_box.configure(state='disabled')
            self.stop_button.configure(state='normal');self.canvas.itemconfigure(self.message_item,text='等待端點使用者同意…')
        self.background(work,done)

    def show_native_diagnostics(self):
        import json
        engine=self.engine
        if not engine or not getattr(engine,'native_media',False):return
        existing=getattr(self,'diagnostic_window',None)
        if existing is not None and existing.winfo_exists():
            self.diagnostic_refresh();existing.deiconify();existing.lift();return
        window=self.tk.Toplevel(self.root);window.title('本機輸入診斷');window.geometry('680x600')
        self.diagnostic_window=window
        self.ttk.Label(window,text='手動快照，請按「更新數據」取得最新計數。queued 是排入；transmitted 只代表交給通道，不代表端點已執行。',padding=12,wraplength=640).pack(fill='x')
        text=self.tk.Text(window,wrap='none');text.pack(fill='both',expand=True,padx=12)
        def refresh():
            current_engine=self.engine
            current=current_engine.diagnostics_snapshot() if current_engine and getattr(current_engine,'native_media',False) else None
            text.configure(state='normal');text.delete('1.0','end')
            text.insert('1.0',json.dumps(current,ensure_ascii=False,indent=2) if current is not None else '尚無診斷數據，或本次協助已結束。')
            text.configure(state='disabled')
        self.ttk.Button(window,text='更新數據',command=refresh).pack(pady=12)
        self.diagnostic_refresh=refresh
        refresh() # Nonmodal: no grab, wait_window, message box or authority changes.

    def clear_frame(self,message='協助已結束'):
        if self.image:self.image.close();self.image=None
        self.photo=None
        if hasattr(self,'canvas') and self.canvas.winfo_exists():
            self.canvas.itemconfigure(self.screen_item,image='');self.canvas.itemconfigure(self.message_item,text=message)
            try:self.canvas.grab_release()
            except self.tk.TclError:pass

    def stop_session(self):
        if self.fullscreen:self._toggle_canvas_fullscreen()
        if self.engine:self.engine.stop();self.engine=None
        for name,settings in (('native_window_button',{'state':'disabled'}),('fullscreen_button',{'text':'全螢幕／還原'}),('display_box',{'state':'readonly'})):
            widget=getattr(self,name,None)
            if widget is not None and widget.winfo_exists():widget.configure(**settings)
        actions=getattr(self,'native_actions',None)
        if actions is not None and actions.winfo_exists():actions.pack_forget()
        self.clear_frame();self.metric.set('未連線');self.status.set('協助已停止；已停止傳送輸入。')
        if hasattr(self,'stop_button') and self.stop_button.winfo_exists():
            self.stop_button.configure(state='disabled');self.device_box.configure(state='readonly');self.mode_box.configure(state='readonly');self.quality_box.configure(state='readonly');self.selection_changed()

    def render(self):
        if not self.image or self.closing.is_set():return
        from PIL import Image,ImageTk
        native=self.display.get().startswith('100%')
        self.rect=viewport(self.image.size,(max(1,self.canvas.winfo_width()),max(1,self.canvas.winfo_height())),native=native)
        x,y,w,h=self.rect
        self.canvas.configure(scrollregion=(0,0,max(self.canvas.winfo_width(),x+w),max(self.canvas.winfo_height(),y+h)))
        scaled=self.image if (w,h)==self.image.size else self.image.resize((w,h),Image.Resampling.LANCZOS)
        try:self.photo=ImageTk.PhotoImage(scaled,master=self.root)
        finally:
            if scaled is not self.image:scaled.close()
        self.canvas.coords(self.screen_item,x,y);self.canvas.itemconfigure(self.screen_item,image=self.photo)
        self.update_metric()

    def update_metric(self):
        if not self.engine:return
        text='協助進行中' if self.engine.session['status']=='active' else '等待同意'
        if self.image:
            text+=f' · {self.image.width}×{self.image.height} · {self.engine.stats.get("codec",self.frame_codec)} · {round(self.rect[2]/self.image.width*100)}%'
        self.metric.set(text)

    def display_changed(self,event=None):
        self.focus_out()
        if self.display.get().startswith('100%'):
            self.hscroll.grid(row=1,column=0,sticky='ew');self.vscroll.grid(row=0,column=1,sticky='ns')
        else:self.hscroll.grid_remove();self.vscroll.grid_remove()
        self.canvas.xview_moveto(0);self.canvas.yview_moveto(0);self.resize()

    def toggle_display(self):
        self.display.set('符合視窗' if self.display.get().startswith('100%') else '100% 原始大小');self.display_changed()

    def resize(self,event=None):
        if self.resize_job:
            try:self.root.after_cancel(self.resize_job)
            except self.tk.TclError:pass
        self.resize_job=self.root.after(100,self.render)

    def tick(self):
        if self.closing.is_set():return
        for _ in range(16):
            try:action=self.tray_actions.get_nowait()
            except queue.Empty:break
            action()
            if self.closing.is_set():return
        while True:
            try:done,result,error=self.jobs.get_nowait()
            except queue.Empty:break
            self.busy=False;done(result,error)
        engine=self.engine
        if engine:
            update,error=engine.take()
            if error:
                self.stop_session();self.status.set('連線已停止：'+error)
            elif update:
                packet,image=update
                if packet['status'] not in ('requested','active'):
                    if image:image.close()
                    self.stop_session();self.status.set('協助已結束：'+(packet.get('ended_reason') or packet['status']))
                else:
                    if packet.get('admin_control') and not packet.get('desktop_epoch'):
                        self.clear_frame('Windows 正在切換桌面，暫停操作…')
                    if image:
                        if self.image:self.image.close()
                        self.image=image;self.render()
                        if packet.get('admin_control'):
                            epoch,seq=packet.get('desktop_epoch'),packet.get('frame_seq')
                            self.root.after_idle(lambda e=engine,p=epoch,s=seq:e.presented(p,s))
                    active=packet['status']=='active'
                    if getattr(engine,'native_media',False):
                        if not self.native_actions.winfo_manager():self.native_actions.pack(fill='x',pady=(0,8),before=self.screen)
                        self.native_window_button.configure(state='normal' if active else 'disabled')
                        self.fullscreen_button.configure(text='放大操作視窗／還原')
                        self.display_box.configure(state='disabled')
                        self.canvas.itemconfigure(self.message_item,text='請按「操作遠端視窗」，在獨立影像視窗內使用鍵鼠。' if active else '等待端點使用者同意…')
                        self.metric.set('原生 H.264／WebRTC · 內部預覽')
                        self.status.set('停止協助、登出或關閉仍會立即使本機輸入授權失效。')
                        self.root.after(30,self.tick);return
                    fresh=active and time.monotonic()<engine.fresh_until
                    self.canvas.itemconfigure(self.message_item,text='' if fresh else '畫面更新中，暫停操作' if active else '等待端點使用者同意…')
                    self.update_metric()
                    prefix=('管理員協助 · '+('UAC 安全桌面' if packet.get('desktop')=='winlogon' else '一般／提權桌面')) if packet.get('admin_control') else '一般桌面'+('控制模式' if packet['mode']=='control' else '僅檢視')
                    self.status.set(prefix+'；畫面中斷會暫停輸入，最長 10 分鐘。')
            elif self.image and time.monotonic()>engine.fresh_until:self.canvas.itemconfigure(self.message_item,text='畫面更新中，暫停操作')
        self.root.after(30,self.tick)

    def position(self,event,release=False):
        point=pointer(self.canvas.canvasx(event.x),self.canvas.canvasy(event.y),self.rect)
        if point:self.last_point=point
        return point or (self.last_point if release else None)

    def motion(self,event):
        if self.fullscreen and event.y<=8:self.show_toolbar()
        point=self.position(event)
        if point and self.engine:self.engine.send({'type':'move',**point})

    def button(self,event,number,down):
        if not self.engine:return 'break'
        point=self.position(event,release=not down)
        if not point:return 'break'
        self.canvas.focus_set()
        sent=self.engine.send({'type':'button','button':{1:'left',2:'middle',3:'right'}[number],'down':down,**point})
        if sent and down:self.canvas.grab_set()
        if not down:
            try:self.canvas.grab_release()
            except self.tk.TclError:pass
        return 'break'

    def wheel(self,event):
        point=self.position(event)
        if point and self.engine and event.delta:
            delta=max(-1200,min(1200,int(event.delta/120)*120 or (120 if event.delta>0 else -120)))
            self.engine.send({'type':'scroll','delta':delta,**point})
        return 'break'

    def key(self,event,down):
        # Reserved local escape chord is handled by the root binding.
        if event.keysym=='F12' and event.state & 0x0001 and event.state & 0x0004 and event.state & 0x20000:
            if down:self.toggle_fullscreen()
            return 'break'
        if self.engine and event.keycode in KEYS:self.engine.send({'type':'key','key':event.keycode,'down':down})
        return 'break'

    def focus_out(self,event=None):
        if event is not None:
            if self.engine:self.root.after_idle(lambda:self.focus_out() if self.root.focus_get() is not self.canvas else None)
            return
        if self.engine:self.engine.send({'type':'release_all'})

    def activate_native_window(self,toggle_maximize=False):
        engine=self.engine
        if not engine or not getattr(engine,'native_media',False):return False
        queued=engine.activate_window(toggle_maximize)
        self.status.set('已要求帶起遠端操作視窗；請在影像視窗內操作。' if queued else '遠端影像視窗仍在建立，請稍候再按「操作遠端視窗」。')
        return queued

    def toggle_fullscreen(self):
        if self.engine and getattr(self.engine,'native_media',False):
            self.activate_native_window(True);return 'break'
        return self._toggle_canvas_fullscreen()

    def _toggle_canvas_fullscreen(self):
        if not hasattr(self,'screen') or not self.screen.winfo_exists():return 'break'
        self.focus_out();self.fullscreen=not self.fullscreen
        if self.fullscreen:
            self.fullscreen_layout=[(child,child.pack_info()) for child in self.body.winfo_children() if child.winfo_manager()=='pack']
            for child,info in self.fullscreen_layout:child.pack_forget()
            self.header.pack_forget();self.footer.pack_forget();self.body.configure(padding=0)
            self.screen.pack(fill='both',expand=True);self.show_toolbar()
        else:
            if self.toolbar_job:self.root.after_cancel(self.toolbar_job);self.toolbar_job=None
            self.fullbar.place_forget();self.screen.pack_forget()
            self.header.pack(fill='x',before=self.body);self.footer.pack(fill='x');self.body.configure(padding=22)
            for child,info in self.fullscreen_layout:child.pack(**info)
            self.fullscreen_layout=[]
        self.root.attributes('-fullscreen',self.fullscreen)
        self.canvas.focus_set();self.resize()
        return 'break'

    def show_toolbar(self):
        self.fullbar.place(relx=.5,y=0,anchor='n');self.fullbar.lift();self.schedule_toolbar_hide()

    def schedule_toolbar_hide(self):
        if self.toolbar_job:self.root.after_cancel(self.toolbar_job)
        def hide():
            self.toolbar_job=None
            if not self.fullscreen:return
            x,y=self.fullbar.winfo_pointerxy();widget=self.root.winfo_containing(x,y)
            if widget and str(widget).startswith(str(self.fullbar)):self.schedule_toolbar_hide()
            else:self.fullbar.place_forget()
        self.toolbar_job=self.root.after(1800,hide)

    def logout(self):
        if self.busy:return
        self.stop_session();client=self.client;self.client=None
        if client:threading.Thread(target=client.logout,name='GuardDesk viewer logout',daemon=True).start()
        self.user.set('');self.password.set('');self.status.set('已登出');self.login_screen()

    def close(self):
        if self.closing.is_set():return
        self.closing.set()
        if self.engine:self.engine.stop()
        self.clear_frame('')
        if self.client:threading.Thread(target=self.client.logout,name='GuardDesk viewer logout',daemon=True).start()
        if self.tray:self.tray.close();self.tray=None
        self.root.destroy()

    def window_close(self):
        if not self.tray or not self.tray.added:self.close();return
        if self.busy:self.status.set('正在處理請求，完成後即可縮至通知區。');return
        if self.engine:self.stop_session()
        if self.fullscreen:self.toggle_fullscreen()
        self.hidden=True;self.root.withdraw()

    def show_from_tray(self):
        if self.closing.is_set():return
        self.hidden=False;self.root.deiconify();self.root.lift();self.root.focus_force();self.refresh()


def run(argv=None,*,tray=False):
    import os
    if os.name!='nt':raise OSError('桌面遠端協助僅支援 Windows')
    parser=argparse.ArgumentParser(description='GuardDesk 獨立 Windows 遠端協助')
    parser.add_argument('--server');parser.add_argument('--workstation',action='store_true');parser.add_argument('--ca')
    source=parser.add_mutually_exclusive_group();source.add_argument('--connection');source.add_argument('--agent-config')
    args=parser.parse_args(argv)
    server=args.server or ('' if args.workstation else 'http://127.0.0.1:8788');ca=args.ca
    if args.connection or args.agent_config:
        if not args.workstation or args.server or args.ca:raise ValueError('連線設定請搭配 --workstation，不可同時覆寫位址或 CA')
        from .mis_support import connection
        server,ca=connection(args.connection or args.agent_config,agent=bool(args.agent_config))
    import ctypes
    try:ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except (AttributeError,OSError):pass
    import tkinter as tk
    root=tk.Tk();RemoteViewer(root,server,workstation=args.workstation,ca=ca,tray=tray);root.mainloop()
