Output demo/hero.gif

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 13
Set Width 1000
Set Height 520
Set Padding 12
Set LineHeight 1.2
Set LetterSpacing 0
Set Theme "Catppuccin Mocha"

Set TypingSpeed 0ms

Type "cat testdata/queries.sql"
Enter
Sleep 3s

Type "cat testdata/queries.sql | anon"
Enter
Sleep 4s

Type "cat testdata/queries.sql | anon | claude -p 'explain those queries' | anon restore"
Enter
Sleep 6s
