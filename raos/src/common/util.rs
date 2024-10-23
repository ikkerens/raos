pub(crate) trait NoneIfEmpty {
    fn none_if_empty(self) -> Self;
}

impl NoneIfEmpty for Option<String> {
    fn none_if_empty(self) -> Self {
        self.and_then(|value| if value.is_empty() { None } else { Some(value) })
    }
}
