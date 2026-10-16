VERSION 2.00
Begin Form Form1
   Caption         =   "Types"
   ClientHeight    =   1500
   ClientLeft      =   1000
   ClientTop       =   1000
   ClientWidth     =   3000
   Height          =   1900
   Left            =   940
   LinkTopic       =   "Form1"
   ScaleHeight     =   1500
   ScaleWidth      =   3000
   Top             =   660
   Width           =   3120
   Begin CommandButton Command1
      Caption         =   "Go"
      Height          =   495
      Index           =   0
      Left            =   240
      TabIndex        =   0
      Top             =   240
      Width           =   1215
   End
End

Sub Command1_Click (Index As Integer)
    Mark = "CASE event_index_param"
    Tmp = Index
End Sub

Sub Form_KeyPress (KeyAscii As Integer)
    Mark = "CASE event_keyascii_param"
    Tmp = KeyAscii
End Sub

Sub Form_Load ()
    Main
End Sub
