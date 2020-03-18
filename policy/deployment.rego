package main

allowed_zones = "us-east-1a"

#allowed_zones = {"name": "us-east-2a", "n": "ap-south-1a"}

#q[name] {allowed_zones[_].name = name}

deny [msg] {
    version := input.resource_changes[_].change.after.availability_zones[_]
    #version != allowed_zones.name & allowed_zones.n
    version != allowed_zones
    msg := sprintf("should be using python3, currently using python %v", [allowed_zones])
}


maximum_size = 3
deny [msg] {
    Given_max_size := input.resource_changes[_].change.after.max_size
    Given_max_size != maximum_size
    msg := sprintf("Allowed value is max 3, currently you have assainged value as %v", [Given_max_size])

}

is_pascal_case(string) {
    re_match(`^([A-Z][a-z0-9]+)+`, string)
}

Tag_prefix = "cloud_automation_phase5"
deny [msg] {
    Given_tags := input.resource_changes[_].change.after.tags
    Given_tags != Tag_prefix
    #given_tages == output
    msg := sprintf("Tags are mandatory, currently you have not assainged any tasg the value is %v", [Given_tags])

}
