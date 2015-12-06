"""Flash message constants for admin package.

This module contains all of the string constants used for flash messages. The
attributes in the message classes should be tuples with two elements. The first
element is the message string. The second element is the message category. This
enables flash messages in each category to take on unique visual traits, by
passing a CSS class name behind the scenes. If you do not wish for a flash
message to be displayed for a particular event, set the attribute to None
instead of the standard tuple.

"""

from .. import FlashCategory


class Messages:
    pass
