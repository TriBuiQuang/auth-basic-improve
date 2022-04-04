## Commit conventions
 The rules about commit to git, please follow it if you want contributes something.

### [type] body


   |   Type       | body                                                                                      |
   |--------------|-------------------------------------------------------------------------------------------|
   |feat          | Add more feature                                                                          | 
   |fix           | Fix bugs, fix error in codebase                                                           | 
   |refactor      | Edit code bug not fix bug and not add new feature or sometime bug is fixed from refactor  | 
   |docs          | Add/edit document                                                                         | 
   |chore         | Fix little things not related with code                                                   | 
   |style         | Change not change the meaning of code like css/ui                                         | 
   |perf          | Improve performance                                                                       | 
   |vendor        | update package, dependencies version                                                      | 

Example :
```
I update new feature authenticate
Then my commit is:
git commit -m "[feat] Add authenticate"
```