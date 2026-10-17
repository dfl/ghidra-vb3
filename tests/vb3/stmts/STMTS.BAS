Option Explicit

Global Mark As String
Global Tmp As Variant
Global S As String
Global I As Integer
Global L As Long
Global D As Double
Global V As Variant
Global A() As Integer

Sub Main ()
    ReDim A(1 To 3)
    Case_baseline
    Case_beep
    Case_chdir
    Case_chdrive
    Case_mkdir
    Case_rmdir
    Case_kill
    Case_name
    Case_open_output
    Case_open_input
    Case_open_binary
    Case_open_random
    Case_close
    Case_close_all
    Case_reset
    Case_print_file
    Case_write_file
    Case_input_file
    Case_line_input
    Case_get
    Case_put
    Case_seek_stmt
    Case_randomize
    Case_sendkeys
    Case_appactivate
    Case_date_stmt
    Case_time_stmt
    Case_erase
    Case_error_stmt
    Case_on_error
    Case_doevents
    Case_load
    Case_unload
    Case_show
    Case_cls
    Case_pset
    Case_line_method
    Case_circle
    Case_print_method
    Case_clipboard
    Case_msgbox_fn
    Case_msgbox_stmt
    Case_inputbox
    Case_shell
    Case_timer
    Case_now
    Case_date_fn
    Case_time_fn
    Case_dateserial
    Case_timeserial
    Case_datevalue
    Case_year
    Case_weekday
    Case_format
    Case_dir
    Case_curdir
    Case_environ
    Case_command
    Case_freefile
    Case_eof
    Case_lof
    Case_loc
    Case_seek_fn
    Case_filelen
    Case_input_fn
    Case_rnd
    Case_loadpicture
    Case_qbcolor
    Case_rgb
    Case_chr
    Case_asc
    Case_len
    Case_mid
    Case_left
    Case_right
    Case_instr
    Case_lcase
    Case_ucase
    Case_ltrim
    Case_trim
    Case_space
    Case_string
    Case_str
    Case_val
    Case_hex
    Case_oct
    Case_abs
    Case_int
    Case_fix
    Case_sgn
    Case_sqr
    Case_sin
    Case_cos
    Case_tan
    Case_atn
    Case_exp
    Case_log
    Case_cint
    Case_clng
    Case_csng
    Case_cdbl
    Case_ccur
    Case_cstr
    Case_cvar
    Case_isnull
    Case_isempty
    Case_isnumeric
    Case_isdate
    Case_vartype
    Case_lbound
    Case_ubound
    Case_err_fn
    Case_error_fn
End Sub

Sub Case_baseline ()
    Mark = "CASE baseline"
End Sub

Sub Case_beep ()
    Mark = "CASE beep"
    Beep
End Sub

Sub Case_chdir ()
    Mark = "CASE chdir"
    ChDir "C:\"
End Sub

Sub Case_chdrive ()
    Mark = "CASE chdrive"
    ChDrive "C"
End Sub

Sub Case_mkdir ()
    Mark = "CASE mkdir"
    MkDir "C:\STMTS"
End Sub

Sub Case_rmdir ()
    Mark = "CASE rmdir"
    RmDir "C:\STMTS"
End Sub

Sub Case_kill ()
    Mark = "CASE kill"
    Kill "C:\STMTS.TMP"
End Sub

Sub Case_name ()
    Mark = "CASE name"
    Name "C:\A.TMP" As "C:\B.TMP"
End Sub

Sub Case_open_output ()
    Mark = "CASE open_output"
    Open "C:\S.TMP" For Output As #1
End Sub

Sub Case_open_input ()
    Mark = "CASE open_input"
    Open "C:\S.TMP" For Input As #1
End Sub

Sub Case_open_binary ()
    Mark = "CASE open_binary"
    Open "C:\S.TMP" For Binary As #1
End Sub

Sub Case_open_random ()
    Mark = "CASE open_random"
    Open "C:\S.TMP" For Random As #1 Len = 16
End Sub

Sub Case_close ()
    Mark = "CASE close"
    Close #1
End Sub

Sub Case_close_all ()
    Mark = "CASE close_all"
    Close
End Sub

Sub Case_reset ()
    Mark = "CASE reset"
    Reset
End Sub

Sub Case_print_file ()
    Mark = "CASE print_file"
    Print #1, "x"
End Sub

Sub Case_write_file ()
    Mark = "CASE write_file"
    Write #1, "x"
End Sub

Sub Case_input_file ()
    Mark = "CASE input_file"
    Input #1, S
End Sub

Sub Case_line_input ()
    Mark = "CASE line_input"
    Line Input #1, S
End Sub

Sub Case_get ()
    Mark = "CASE get"
    Get #1, 1, I
End Sub

Sub Case_put ()
    Mark = "CASE put"
    Put #1, 1, I
End Sub

Sub Case_seek_stmt ()
    Mark = "CASE seek_stmt"
    Seek #1, 1
End Sub

Sub Case_randomize ()
    Mark = "CASE randomize"
    Randomize
End Sub

Sub Case_sendkeys ()
    Mark = "CASE sendkeys"
    SendKeys "x"
End Sub

Sub Case_appactivate ()
    Mark = "CASE appactivate"
    AppActivate "Program Manager"
End Sub

Sub Case_date_stmt ()
    Mark = "CASE date_stmt"
    Date$ = "01-01-1994"
End Sub

Sub Case_time_stmt ()
    Mark = "CASE time_stmt"
    Time$ = "12:00:00"
End Sub

Sub Case_erase ()
    Mark = "CASE erase"
    Erase A
End Sub

Sub Case_error_stmt ()
    Mark = "CASE error_stmt"
    Error 5
End Sub

Sub Case_on_error ()
    Mark = "CASE on_error"
    On Error Resume Next
    Tmp = 1
End Sub

Sub Case_end_stmt ()
    Mark = "CASE end_stmt"
    End
End Sub

Sub Case_doevents ()
    Mark = "CASE doevents"
    I = DoEvents()
End Sub

Sub Case_load ()
    Mark = "CASE load"
    Load Form1
End Sub

Sub Case_unload ()
    Mark = "CASE unload"
    Unload Form1
End Sub

Sub Case_show ()
    Mark = "CASE show"
    Form1.Show
End Sub

Sub Case_cls ()
    Mark = "CASE cls"
    Form1.Cls
End Sub

Sub Case_pset ()
    Mark = "CASE pset"
    Form1.PSet (1, 1)
End Sub

Sub Case_line_method ()
    Mark = "CASE line_method"
    Form1.Line (0, 0)-(10, 10)
End Sub

Sub Case_circle ()
    Mark = "CASE circle"
    Form1.Circle (5, 5), 2
End Sub

Sub Case_print_method ()
    Mark = "CASE print_method"
    Form1.Print "x"
End Sub

Sub Case_clipboard ()
    Mark = "CASE clipboard"
    Clipboard.SetText "x"
End Sub

Sub Case_msgbox_fn ()
    Mark = "CASE msgbox_fn"
    I = MsgBox("x", 1, "t")
End Sub

Sub Case_msgbox_stmt ()
    Mark = "CASE msgbox_stmt"
    MsgBox "x"
End Sub

Sub Case_inputbox ()
    Mark = "CASE inputbox"
    S = InputBox$("x")
End Sub

Sub Case_shell ()
    Mark = "CASE shell"
    I = Shell("NOTEPAD.EXE", 1)
End Sub

Sub Case_timer ()
    Mark = "CASE timer"
    D = Timer
End Sub

Sub Case_now ()
    Mark = "CASE now"
    D = Now
End Sub

Sub Case_date_fn ()
    Mark = "CASE date_fn"
    S = Date$
End Sub

Sub Case_time_fn ()
    Mark = "CASE time_fn"
    S = Time$
End Sub

Sub Case_dateserial ()
    Mark = "CASE dateserial"
    D = DateSerial(1994, 1, 1)
End Sub

Sub Case_timeserial ()
    Mark = "CASE timeserial"
    D = TimeSerial(12, 0, 0)
End Sub

Sub Case_datevalue ()
    Mark = "CASE datevalue"
    D = DateValue("1-1-94")
End Sub

Sub Case_year ()
    Mark = "CASE year"
    I = Year(D)
End Sub

Sub Case_weekday ()
    Mark = "CASE weekday"
    I = Weekday(D)
End Sub

Sub Case_format ()
    Mark = "CASE format"
    S = Format$(D, "0.00")
End Sub

Sub Case_dir ()
    Mark = "CASE dir"
    S = Dir$("C:\*.*")
End Sub

Sub Case_curdir ()
    Mark = "CASE curdir"
    S = CurDir$
End Sub

Sub Case_environ ()
    Mark = "CASE environ"
    S = Environ$("PATH")
End Sub

Sub Case_command ()
    Mark = "CASE command"
    S = Command$
End Sub

Sub Case_freefile ()
    Mark = "CASE freefile"
    I = FreeFile
End Sub

Sub Case_eof ()
    Mark = "CASE eof"
    I = EOF(1)
End Sub

Sub Case_lof ()
    Mark = "CASE lof"
    L = LOF(1)
End Sub

Sub Case_loc ()
    Mark = "CASE loc"
    L = Loc(1)
End Sub

Sub Case_seek_fn ()
    Mark = "CASE seek_fn"
    L = Seek(1)
End Sub

Sub Case_filelen ()
    Mark = "CASE filelen"
    L = FileLen("C:\AUTOEXEC.BAT")
End Sub

Sub Case_input_fn ()
    Mark = "CASE input_fn"
    S = Input$(1, #1)
End Sub

Sub Case_rnd ()
    Mark = "CASE rnd"
    D = Rnd
End Sub

Sub Case_loadpicture ()
    Mark = "CASE loadpicture"
    Form1.Picture = LoadPicture("")
End Sub

Sub Case_qbcolor ()
    Mark = "CASE qbcolor"
    L = QBColor(1)
End Sub

Sub Case_rgb ()
    Mark = "CASE rgb"
    L = RGB(1, 2, 3)
End Sub

Sub Case_chr ()
    Mark = "CASE chr"
    S = Chr$(65)
End Sub

Sub Case_asc ()
    Mark = "CASE asc"
    I = Asc("A")
End Sub

Sub Case_len ()
    Mark = "CASE len"
    I = Len(S)
End Sub

Sub Case_mid ()
    Mark = "CASE mid"
    S = Mid$(S, 1, 1)
End Sub

Sub Case_left ()
    Mark = "CASE left"
    S = Left$(S, 1)
End Sub

Sub Case_right ()
    Mark = "CASE right"
    S = Right$(S, 1)
End Sub

Sub Case_instr ()
    Mark = "CASE instr"
    I = InStr(S, "x")
End Sub

Sub Case_lcase ()
    Mark = "CASE lcase"
    S = LCase$(S)
End Sub

Sub Case_ucase ()
    Mark = "CASE ucase"
    S = UCase$(S)
End Sub

Sub Case_ltrim ()
    Mark = "CASE ltrim"
    S = LTrim$(S)
End Sub

Sub Case_trim ()
    Mark = "CASE trim"
    S = Trim$(S)
End Sub

Sub Case_space ()
    Mark = "CASE space"
    S = Space$(3)
End Sub

Sub Case_string ()
    Mark = "CASE string"
    S = String$(3, "x")
End Sub

Sub Case_str ()
    Mark = "CASE str"
    S = Str$(I)
End Sub

Sub Case_val ()
    Mark = "CASE val"
    D = Val(S)
End Sub

Sub Case_hex ()
    Mark = "CASE hex"
    S = Hex$(I)
End Sub

Sub Case_oct ()
    Mark = "CASE oct"
    S = Oct$(I)
End Sub

Sub Case_abs ()
    Mark = "CASE abs"
    D = Abs(D)
End Sub

Sub Case_int ()
    Mark = "CASE int"
    D = Int(D)
End Sub

Sub Case_fix ()
    Mark = "CASE fix"
    D = Fix(D)
End Sub

Sub Case_sgn ()
    Mark = "CASE sgn"
    I = Sgn(D)
End Sub

Sub Case_sqr ()
    Mark = "CASE sqr"
    D = Sqr(D)
End Sub

Sub Case_sin ()
    Mark = "CASE sin"
    D = Sin(D)
End Sub

Sub Case_cos ()
    Mark = "CASE cos"
    D = Cos(D)
End Sub

Sub Case_tan ()
    Mark = "CASE tan"
    D = Tan(D)
End Sub

Sub Case_atn ()
    Mark = "CASE atn"
    D = Atn(D)
End Sub

Sub Case_exp ()
    Mark = "CASE exp"
    D = Exp(D)
End Sub

Sub Case_log ()
    Mark = "CASE log"
    D = Log(D)
End Sub

Sub Case_cint ()
    Mark = "CASE cint"
    I = CInt(D)
End Sub

Sub Case_clng ()
    Mark = "CASE clng"
    L = CLng(D)
End Sub

Sub Case_csng ()
    Mark = "CASE csng"
    D = CSng(D)
End Sub

Sub Case_cdbl ()
    Mark = "CASE cdbl"
    D = CDbl(I)
End Sub

Sub Case_ccur ()
    Mark = "CASE ccur"
    V = CCur(D)
End Sub

Sub Case_cstr ()
    Mark = "CASE cstr"
    S = CStr(D)
End Sub

Sub Case_cvar ()
    Mark = "CASE cvar"
    V = CVar(D)
End Sub

Sub Case_isnull ()
    Mark = "CASE isnull"
    I = IsNull(V)
End Sub

Sub Case_isempty ()
    Mark = "CASE isempty"
    I = IsEmpty(V)
End Sub

Sub Case_isnumeric ()
    Mark = "CASE isnumeric"
    I = IsNumeric(V)
End Sub

Sub Case_isdate ()
    Mark = "CASE isdate"
    I = IsDate(V)
End Sub

Sub Case_vartype ()
    Mark = "CASE vartype"
    I = VarType(V)
End Sub

Sub Case_lbound ()
    Mark = "CASE lbound"
    I = LBound(A)
End Sub

Sub Case_ubound ()
    Mark = "CASE ubound"
    I = UBound(A)
End Sub

Sub Case_err_fn ()
    Mark = "CASE err_fn"
    I = Err
End Sub

Sub Case_error_fn ()
    Mark = "CASE error_fn"
    S = Error$
End Sub

