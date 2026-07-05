variable "name_prefix" { type = string }
variable "tags" { type = map(string) default = {} }
variable "enabled" { type = bool default = true }
