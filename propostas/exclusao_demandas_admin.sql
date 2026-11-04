-- Instalado no Supabase em 2026-11-04. Mantido para auditoria e repetibilidade.
-- A interface ainda requer validacao funcional antes da publicacao.
-- Somente administrador ativo, com sessao autenticada recentemente.
CREATE OR REPLACE FUNCTION public.excluir_demanda_administrador(p_demanda_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE v_iat bigint;
BEGIN
 IF auth.uid() IS NULL OR NOT EXISTS (
  SELECT 1 FROM public.perfis
  WHERE id=auth.uid() AND ativo=true AND perfil='administrador'
 ) THEN RAISE EXCEPTION 'Somente administrador ativo pode excluir demandas'; END IF;
 v_iat := NULLIF(auth.jwt()->>'iat','')::bigint;
 IF v_iat IS NULL OR EXTRACT(EPOCH FROM clock_timestamp())-v_iat>180 THEN
  RAISE EXCEPTION 'Confirme novamente a senha antes da exclusao';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM public.demandas_recepcao WHERE id=p_demanda_id FOR UPDATE)
 THEN RAISE EXCEPTION 'Demanda nao encontrada'; END IF;
 DELETE FROM public.demandas_denunciantes WHERE demanda_id=p_demanda_id;
 DELETE FROM public.demandas_recepcao WHERE id=p_demanda_id;
END $$;
REVOKE ALL ON FUNCTION public.excluir_demanda_administrador(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.excluir_demanda_administrador(uuid) TO authenticated;
-- Administrador precisa listar arquivos mesmo apos a exclusao do registro.
DROP POLICY IF EXISTS demandas_saj_admin_ler_orfaos ON storage.objects;
CREATE POLICY demandas_saj_admin_ler_orfaos ON storage.objects
FOR SELECT TO authenticated USING (
 bucket_id='demandas-saj' AND EXISTS (
 SELECT 1 FROM public.perfis p WHERE p.id=(SELECT auth.uid()) AND p.ativo AND p.perfil='administrador'
 ));
DROP POLICY IF EXISTS demandas_saj_admin_excluir ON storage.objects;
CREATE POLICY demandas_saj_admin_excluir ON storage.objects
FOR DELETE TO authenticated USING (
 bucket_id='demandas-saj' AND EXISTS (
 SELECT 1 FROM public.perfis p WHERE p.id=(SELECT auth.uid()) AND p.ativo AND p.perfil='administrador'
 ));
