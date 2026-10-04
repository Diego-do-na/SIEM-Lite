// This is the only thing that all the other modules have in common, the prefix for all resources. That's why it deserves its own file!
locals {
    prefix = "${var.project_name}-${var.environment}"
}