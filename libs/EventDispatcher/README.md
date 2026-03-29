This project is about implement a Job Scheduler (also called an Event scheduler) Library.
Using this library :
1. There is no need of deploying any locking
2. All execution flows are serialized
3. No concurrent access
4. The execution unit can "fork" multiple execution units, all of which are serialized
