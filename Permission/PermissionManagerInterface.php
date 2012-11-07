<?php

/**
 * This file is part of the AnoSecurityBundle
 *
 * (c) anonymation <contact@anonymation.com>
 *
 */

namespace Ano\Bundle\SecurityBundle\Permission;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;

/**
 * Abstraction of Symfony2's ACLs/ACEs common operations
 *
 * @author Benjamin Dulau <benjamin.dulau@anonymation.com>
 */
interface PermissionManagerInterface
{
    const ON_OBJECT = 1;
    const ON_CLASS = 2;

    const TO_USER = 10;
    const TO_ROLE = 11;

    const FROM_USER = 20;
    const FROM_ROLE = 21;

    /**
     * @param mixed $privileges
     * @param int   $onType
     * @param mixed $onValue
     * @param int   $toType
     * @param mixed $toValue
     *
     * @return mixed
     */
    public function grantPrivileges($privileges, $onType, $onValue, $toType, $toValue);

    /**
     * @param mixed $privileges
     * @param int   $onType
     * @param mixed $onValue
     * @param int   $fromType
     * @param mixed $fromValue
     *
     * @return mixed
     */
    public function revokePrivileges($privileges, $onType, $onValue, $fromType, $fromValue);

    /**
     * @param array $role
     *
     * @return mixed
     */
    public function createRoleIdentities(array $role);

    /**
     * @param int   $onType
     * @param mixed $onValue
     *
     * @return mixed
     */
    public function deleteAcls($onType, $onValue);
}