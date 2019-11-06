import re
import logging

class SimplePolicy:

    def __init__(self, policy, logger=None):
        self.policy = policy
        self.logger = logger or logging.getLogger('wsid.policy.simple')

       
    # TODO: precompile regexps and lambdas
    def allowed(self, path, identity):
        for pathpattern, allowed in self.policy.items():
            self.logger.debug("CHECKING path '%s' against CONDITION: '%s'" % (path, pathpattern))
            if re.compile(pathpattern).search(path):
                self.logger.debug("PATH '%s' matches rule '%s'" % (path, pathpattern))
                self.logger.debug("CHECKING identity '%s' against policy '%s'" % (identity, allowed))
                for identity_pattern in allowed:
                    self.logger.debug("CHECKING identity '%s' against allowed pattern '%s'" % (identity, identity_pattern))
                    if re.compile(identity_pattern).search(identity):
                        self.logger.debug("MATCH FOUND!")
                        return True

        return False
                


        
