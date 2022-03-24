"""
 This file is part of nucypher.

 nucypher is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 nucypher is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with nucypher.  If not, see <https://www.gnu.org/licenses/>.
"""

from typing import Callable

from twisted.internet.task import LoopingCall

from nucypher.utilities.logging import Logger


class RestartableTask:
    INTERVAL = 60

    def __init__(self, task_func: Callable):
        self.log = Logger(self.__class__.__name__)
        self.__task = LoopingCall(task_func)

    @property
    def running(self) -> bool:
        return self.__task.running

    def start(self, now: bool = False):
        if not self.running:
            d = self.__task.start(interval=self.INTERVAL, now=now)
            d.addErrback(self.handle_errors)

    def stop(self) -> None:
        if self.running:
            self.__task.stop()

    def handle_errors(self, crash_on_error: bool = False, *args, **kwargs) -> None:
        if args:
            failure = args[0]
            cleaned_traceback = failure.getTraceback().replace('{', '').replace('}', '')  # FIXME: Amazing.
            self.log.warn(f"Unhandled error during operator bonded check: {cleaned_traceback}")
            if crash_on_error:
                failure.raiseException()
        else:
            # Restart on failure
            if not self.running:
                self.log.debug(f"{self.__class__.__name__} crashed, restarting...")
                self.start(now=True)
