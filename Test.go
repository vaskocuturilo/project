type Job struct{
result interface{}
}
func (self *Job) execute() {
// do some work
self.result = ....
}

// an array of jobs
jobs := make([]Job)
jobs.append(jobs, ...)

var wg sync.WaitGroup
wg.Add(len(jobs))
for i, job := range jobs {
go func (idx int, task Job) {
defer wg.Done()
job.execute()
jobs[i].result = job.result
}(i, job)
}
wg.Wait()
