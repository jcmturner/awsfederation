package user

import "time"

type User struct {
	Domain          string
	UserName        string
	DisplayName     string
	Email           string
	Human           bool
	GroupMembership []string
	AuthTime        time.Time
}

//func (u *User) AssumeRole(role, policy string)
