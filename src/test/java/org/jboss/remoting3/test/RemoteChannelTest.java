/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.remoting3.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.xnio.IoUtils.safeClose;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.spec.InvalidKeySpecException;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

import javax.security.sasl.SaslServerFactory;

import org.jboss.remoting3.Channel;
import org.jboss.remoting3.Connection;
import org.jboss.remoting3.Endpoint;
import org.jboss.remoting3.OpenListener;
import org.jboss.remoting3.Registration;
import org.jboss.remoting3.spi.NetworkServerProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.provider.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.spec.DigestPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.sasl.util.ServiceLoaderSaslServerFactory;
import org.xnio.FutureResult;
import org.xnio.IoFuture;
import org.xnio.OptionMap;
import org.xnio.channels.AcceptingChannel;
import org.xnio.channels.ConnectedStreamChannel;

/**
 * Test for remote channel communication.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class RemoteChannelTest extends ChannelTestBase {
    protected static Endpoint endpoint;
    private static AcceptingChannel<? extends ConnectedStreamChannel> streamServer;
    private Connection connection;
    private Registration serviceRegistration;

    static final String ALGORITHM = "digest-md5";
    static final String REALM = "mainRealm";
    static final String USERNAME = "bob";
    static final String PASSWORD = "pass";

    @BeforeClass
    public static void create() throws Exception {
        endpoint = Endpoint.builder().setEndpointName("test").build();
        NetworkServerProvider networkServerProvider = endpoint.getConnectionProviderInterface("remote", NetworkServerProvider.class);
        final SecurityDomain.Builder domainBuilder = SecurityDomain.builder();
        final SimpleMapBackedSecurityRealm mainRealm = new SimpleMapBackedSecurityRealm();
        domainBuilder.addRealm(REALM, mainRealm);
        domainBuilder.setDefaultRealmName(REALM);

        Password password = createPassword();

        mainRealm.setPasswordMap("bob", password);


        final SaslServerFactory saslServerFactory = new ServiceLoaderSaslServerFactory(RemoteChannelTest.class.getClassLoader());
        streamServer = networkServerProvider.createServer(new InetSocketAddress("localhost", 30123), OptionMap.EMPTY, domainBuilder.build(), saslServerFactory);
    }

    @Before
    public void testStart() throws IOException, URISyntaxException, InterruptedException, NoSuchAlgorithmException, InvalidKeySpecException {
        final FutureResult<Channel> passer = new FutureResult<Channel>();
        serviceRegistration = endpoint.registerService("org.jboss.test", new OpenListener() {
            public void channelOpened(final Channel channel) {
                passer.setResult(channel);
            }

            public void registrationTerminated() {
            }
        }, OptionMap.EMPTY);

        Password password = createPassword();
        IoFuture<Connection> futureConnection = AuthenticationContext.empty().with(MatchRule.ALL, AuthenticationConfiguration.EMPTY.useName("bob").usePassword(password).allowSaslMechanisms("DIGEST-MD5")).run(new PrivilegedAction<IoFuture<Connection>>() {
            public IoFuture<Connection> run() {
                try {
                    return endpoint.connect(new URI("remote://localhost:30123"), OptionMap.EMPTY);
                } catch (IOException | URISyntaxException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        connection = futureConnection.get();
        assertNull("No SSLSession", connection.getSslSession());
        IoFuture<Channel> futureChannel = connection.openChannel("org.jboss.test", OptionMap.EMPTY);
        sendChannel = futureChannel.get();
        recvChannel = passer.getIoFuture().get();
        assertNotNull(recvChannel);
        assertNull("No SSLSession", recvChannel.getConnection().getSslSession());
//        assertEquals("bob",recvChannel.getConnection().getUserInfo().getUserName());
    }

    private static Password createPassword() throws NoSuchAlgorithmException, InvalidKeySpecException {
        PasswordFactory factory = PasswordFactory.getInstance(ALGORITHM);
        DigestPasswordAlgorithmSpec dpas = new DigestPasswordAlgorithmSpec(ALGORITHM, USERNAME, REALM);
        EncryptablePasswordSpec encryptableSpec = new EncryptablePasswordSpec(PASSWORD.toCharArray(), dpas);
        return (DigestPassword) factory.generatePassword(encryptableSpec);
    }

    @After
    public void testFinish() {
        safeClose(sendChannel);
        safeClose(recvChannel);
        safeClose(connection);
        serviceRegistration.close();
    }

    @AfterClass
    public static void destroy() throws IOException, InterruptedException {
        safeClose(streamServer);
        safeClose(endpoint);
    }

    @Test
    public void testRefused() throws Exception {
        IoFuture<Connection> futureConnection = endpoint.connect(new URI("remote://localhost:33123"), OptionMap.EMPTY);
        try {
            futureConnection.awaitInterruptibly(2L, TimeUnit.SECONDS);
            if (futureConnection.getStatus() == IoFuture.Status.WAITING) {
                futureConnection.cancel();
            } else {
                safeClose(futureConnection.get());
            }
        } catch (IOException expected) {
            System.out.println("Exception is: " + expected);
            System.out.flush();
            if (expected.getMessage().toLowerCase(Locale.US).contains("refused")) {
                return;
            }
        }
        fail("Expected an IOException with 'refused' in the string");
    }
}
