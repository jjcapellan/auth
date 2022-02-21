## v1.0.1
### New features
* **GetUsersCount() (int, error)** . Gets the current number of registered users.
### Fixes
* Fix: Failed login attempts was not properly banned.  
  
---
## v1.0.0
First version. Basic features was implemented.
* Users management
* Sessions control
* Two factor authentication (login - email)
* Authorization middleware
* User access filter by authorization levels
* Temporally bans for excessive loging attemps against one user from same ip.