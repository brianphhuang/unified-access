/*
 * The Alluxio Open Foundation licenses this work under the Apache License, version 2.0
 * (the "License"). You may not use this work except in compliance with the License, which is
 * available at www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied, as more fully set forth in the License.
 *
 * See the NOTICE file distributed with this work for information regarding copyright ownership.
 */

package alluxio.proxy.s3.auth;

import alluxio.conf.Configuration;
import alluxio.conf.PropertyKey;
import alluxio.proxy.s3.S3Exception;
import alluxio.proxy.s3.signature.AuthorizationV4Validator;

/**
 * Default implementation of {@link Authenticator}. The method {@link #isAuthenticated}
 * returns true by default.
 *
 * When defining how to obtain secret, the following method can be called for
 * authentication:
 *    return AuthorizationV4Validator.validateRequest(
 *                 signedInfo.getStringTosSign(),
 *                 signedInfo.getSignature(),
 *                 secret);
 */
public class AwsAuthenticator implements Authenticator {
  @Override
  public boolean isAuthenticated(AwsAuthInfo authInfo) throws S3Exception {
    return AuthorizationV4Validator.validateRequest(
                 authInfo.getStringTosSign(),
                 authInfo.getSignature(),
                 Configuration.global().getString(
                   PropertyKey.getOrBuildCustom(PropertyKey.Name.S3A_SECRET_KEY
                   + "." + authInfo.getAccessID())));
  }
}
