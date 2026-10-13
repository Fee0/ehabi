use core::ops::{Deref, DerefMut};

use crate::common::SectionId;
use crate::write::Writer;

macro_rules! define_section {
    ($name:ident, $id:ident, $docs:expr) => {
        #[doc=$docs]
        #[derive(Debug, Default)]
        pub struct $name<W: Writer>(pub W);

        impl<W: Writer> $name<W> {
            /// Return the section id.
            #[inline]
            pub fn id(&self) -> SectionId {
                SectionId::$id
            }
        }

        impl<W: Writer> From<W> for $name<W> {
            #[inline]
            fn from(w: W) -> Self {
                $name(w)
            }
        }

        impl<W: Writer> Deref for $name<W> {
            type Target = W;

            #[inline]
            fn deref(&self) -> &W {
                &self.0
            }
        }

        impl<W: Writer> DerefMut for $name<W> {
            #[inline]
            fn deref_mut(&mut self) -> &mut W {
                &mut self.0
            }
        }
    };
}

define_section!(ExIdx, ArmExidx, "A writable `.ARM.exidx` section.");
define_section!(ExTab, ArmExtab, "A writable `.ARM.extab` section.");

/// The two writable EHABI sections.
#[derive(Debug, Default)]
pub struct Sections<W: Writer> {
    /// The `.ARM.exidx` section.
    pub exidx: ExIdx<W>,
    /// The `.ARM.extab` section.
    pub extab: ExTab<W>,
}

impl<W: Writer + Clone> Sections<W> {
    /// Create a new `Sections` using clones of the given `section` writer.
    pub fn new(section: W) -> Self {
        Sections {
            exidx: ExIdx(section.clone()),
            extab: ExTab(section),
        }
    }
}

impl<W: Writer> Sections<W> {
    /// Get the section with the given `id`.
    pub fn get(&self, id: SectionId) -> &W {
        match id {
            SectionId::ArmExidx => &self.exidx,
            SectionId::ArmExtab => &self.extab,
        }
    }

    /// Get the section with the given `id`.
    pub fn get_mut(&mut self, id: SectionId) -> &mut W {
        match id {
            SectionId::ArmExidx => &mut self.exidx,
            SectionId::ArmExtab => &mut self.extab,
        }
    }
}
