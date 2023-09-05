use bgpkit_parser::models::MrtRecord;
use bgpkit_parser::{parse_mrt_record, ParserError};
use std::io::ErrorKind::UnexpectedEof;
use std::io::Read;

/// Alternative to [bgpkit_parser::BgpkitParser] which does not silently hide error messages
pub struct MsgIter<R> {
    reader: R,
    is_finished: bool,
}

impl<R> MsgIter<R> {
    pub fn new(reader: R) -> Self {
        MsgIter {
            reader,
            is_finished: false,
        }
    }
}

impl<R> Iterator for MsgIter<R>
where
    R: Read,
{
    type Item = Result<MrtRecord, ParserError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Check if we returned a fatal error last iteration
        if self.is_finished {
            return None;
        }

        let mut eof_checker = EofChecker {
            reader: &mut self.reader,
            is_start: true,
            started_with_eof: false,
        };

        match parse_mrt_record(&mut eof_checker) {
            Ok(v) => Some(Ok(v)),
            Err(_) if eof_checker.started_with_eof => None,
            Err(e) if is_probably_fatal_error(&e.error) => {
                self.is_finished = true;
                Some(Err(e.error))
            }
            Err(e) => Some(Err(e.error)),
        }
    }
}

/// Guess at which errors are fatal and which ones are specific to a single BGP message
fn is_probably_fatal_error(err: &ParserError) -> bool {
    match err {
        ParserError::IoError(e) => e.kind() == UnexpectedEof,
        ParserError::IoNotEnoughBytes() => true,
        ParserError::EofError(e) => e.kind() == UnexpectedEof,
        ParserError::OneIoError(_) => true,
        ParserError::EofExpected => true,
        ParserError::ParseError(_) => false,
        ParserError::TruncatedMsg(_) => false,
        ParserError::Unsupported(_) => false,
        ParserError::FilterError(_) => false,
    }
}

/// Wraps around a reader and records if it hit the end of the file upon the very first read
struct EofChecker<R: Read> {
    reader: R,
    is_start: bool,
    started_with_eof: bool,
}

impl<R: Read> Read for EofChecker<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let res = self.reader.read(buf);
        if self.is_start {
            self.started_with_eof = res.as_ref().map_or(false, |x| *x == 0);
        }
        self.is_start = false;
        res
    }
}
