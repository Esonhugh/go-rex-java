## Rex Java is Rex library for parsing serialized Java streams.

## Task 1

Looking for the dir structure and read it code. 

Output to answer.md

- what is this project?
- what question does this project solve?
- how it solve this project?

## Task 2

1. creating a go-rex-java folder, ignore if the folder exists
2. following the sturcture of the ruby code you analyze in task 1
3. using golang to rewrite the source code 
4. you shouldn't change any ruby codes
5. make go test and let it coverage over 80%
6. Write golang interface or generic type to help coder and yourself to handle the code and parse processes.
7. follow the code style if the code presents
8. keep your golang mod name as "rexjava"
9. write the readme.md to guide coder/progarmmer how to use this library.
10. write desgin.md to keep your idea about design this project.
11. use less interface{} / any and []interface{} / []any
12. if you can know some string const value can classify to one type or kind, you can use code style like following
```go
type ObjectType string
const (
  Byte ObjectType = "byte"
  ....
)
```
13. rule 12 also apply for the non string const like some value like 0x01.
14. you should make some test let ruby result is equal to golang result.
15. go test should PASS status, if any status is FAIL, means you need to fix.
16. You can't change test like return success to force it pass, which means you can't cheat.
17. example file is abc.ser
18. you should write a ruby test (with lib rex-java) and a golang test (with lib go-rex-java) to try to parse this file and they should have same output.
19. you should not to do something like print the const string or change test or force rewrite the output to force the test pass.
20. you can try command `java -jar ./SerializationDumper-v1.14.jar -r abc.ser` to do the java decoder, add a new go test file and prove they can have same output and don't lost any data
21. change replace hardcoded value in the golang source code and replace with defined const or define a new const with it, if replacement cause the import cycle, you should make const into a safe package and referrence them.
22. create a test to prove that your code can build a java serialized object like abc.ser and decode it back to the same object.