package proglog

default allow = false

allow{
 some i
 data.users[input.id][i] == input.action
} 
